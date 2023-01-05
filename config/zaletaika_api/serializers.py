# import string
import traceback
from datetime import datetime, timedelta

import psycopg2

# import sendgrid
# from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.validators import MinValueValidator
from django.db import connection
from rest_framework import serializers
from rest_framework.serializers import Serializer

from zaletaika_api.utils import (  # ResetCodeManager,; SessionTokenManager,
    UNSET,
    Logger,
    check_can_patient_book_meeting,
    check_doctor_is_verified,
    check_if_exists,
    check_pass,
    check_patient_is_allowed_to_login,
    check_role,
    encrypt,
    generate_token,
    generate_twilio_videoroom_token,
    get_appuser_gid_role,
    get_userid_and_token,
    select_fields_to_json_response,
    sql_generate_qs_with_params_insert,
    sql_generate_qs_with_params_update,
    unaware_to_local,
    utc_to_local,
)
from zaletaika_api.validators import (
    validate_avatar,
    validate_booking_datetime,
    validate_password,
    validate_regrole,
)

#
#
# AUTH LOGIC
#
#


class RegisterUserSerializer(Serializer):
    username = serializers.CharField(required=True, max_length=200)
    email = serializers.EmailField(required=True, max_length=256)
    password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )
    confirmation_password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )
    birth_date = serializers.DateField(required=True)
    avatar = serializers.CharField(required=False, validators=[validate_avatar])
    first_name = serializers.CharField(required=True, max_length=100)
    last_name = serializers.CharField(required=True, max_length=100)
    role = serializers.CharField(
        required=True, max_length=20, validators=[validate_regrole]
    )
    # For DOCTOR role
    occupation = serializers.CharField(
        required=False, allow_blank=False, max_length=200
    )
    # For PATIENT role
    date_of_pregnancy = serializers.DateField(required=False)

    def create(self, validated_data):
        validated_data.get("confirmation_password")
        username = validated_data.get("username")
        email = validated_data.get("email")
        password = validated_data.get("password")
        birth_date = validated_data.get("birth_date")
        avatar = validated_data.get("avatar", None)  # OPTIONAL!!!
        first_name = validated_data.get("first_name")
        last_name = validated_data.get("last_name")
        role = validated_data.get("role")
        if role == "DOCTOR":
            occupation = validated_data.get("occupation")
        else:
            date_of_pregnancy = validated_data.get("date_of_pregnancy")
        with connection.cursor() as cursor:
            try:
                # First, encrypt the password!
                password = encrypt(password)
                # Insert for AppUser
                sql = """
                INSERT INTO AppUser (username, email, password, birthDate,
                firstName, lastName)
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                params = [
                    username,
                    email,
                    password,
                    birth_date,
                    first_name,
                    last_name,
                ]
                cursor.execute(sql, params)
                # Get the instance id right back
                sql = """
                    SELECT id FROM AppUser WHERE username = %s
                """
                params = [username]
                cursor.execute(sql, params)
                user_id = cursor.fetchone()[0]
                # Update avatar if needed
                if avatar is not None:
                    cursor.execute(
                        "UPDATE AppUser SET avatar = %s WHERE id = %s",
                        [avatar, user_id],
                    )

                if role == "DOCTOR":
                    # Insert for DoctorGroup
                    sql = """
                        INSERT INTO DoctorGroup (userId, occupation)
                        VALUES (%s, %s)
                    """
                    params = [user_id, occupation]
                else:
                    # Insert for PatientGroup
                    sql = """
                        INSERT INTO PatientGroup (userId, dateOfPregnancy)
                        VALUES (%s, %s)
                    """
                    params = [user_id, date_of_pregnancy]
                cursor.execute(sql, params)

                # After all of that, create token
                sql = """
                    INSERT INTO AuthToken (userId, token)
                    VALUES (%s, %s)
                """
                token = generate_token(username)
                params = [user_id, token]
                cursor.execute(sql, params)
            except (Exception, psycopg2.Error) as ex:
                Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
                return None
            Logger.write_message("INFO", f"User {email} successfully signed up.")
            return token

    def validate(self, raw_data):
        try:
            if raw_data["password"] != raw_data["confirmation_password"]:
                raise serializers.ValidationError("Passwords don't match!")
            if (
                raw_data["role"] == "DOCTOR"
                and raw_data.get("occupation", None) is None
            ):
                raise serializers.ValidationError(
                    "Did not provide occupation for DOCTOR role."
                )
            if (
                raw_data["role"] == "PATIENT"
                and raw_data.get("date_of_pregnancy", None) is None
            ):
                raise serializers.ValidationError(
                    "Did not provide date of pregnancy for PATIENT role."
                )
        except serializers.ValidationError as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            raise ex
        return raw_data


class LoginUserSerializer(Serializer):
    email = serializers.EmailField(required=True, max_length=256)
    password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )

    def perform_login(self, validated_data):
        token = validated_data.get("token")
        email = validated_data.get("email")
        role = validated_data.get("role")
        Logger.write_message("INFO", f"User {email} successfully logged in.")
        return {"token": token, "role": role}

    def validate(self, raw_data):
        try:
            with connection.cursor() as cursor:
                # We need to check if user even exists
                email = raw_data["email"].strip()
                sql = """
                    SELECT id, password FROM AppUser WHERE email=%s
                """
                params = [email]
                cursor.execute(sql, params)
                res = cursor.fetchone()
                if res is None:
                    raise serializers.ValidationError(
                        "User with this email is not found."
                    )
                user_id = res[0]
                # Check if passwords match
                password_hash = res[1]
                password = raw_data["password"]
                if not check_pass(password, password_hash):
                    raise serializers.ValidationError("Invalid password.")
                # Now, we need to understand what is the group (e.g. role) of this user
                cursor.callproc("get_appuser_group", [user_id])
                role = cursor.fetchone()[0]
                # If it is a patient, then we allow her to login
                # ONLY if she has a doctor assigned already
                if role == "PATIENT":
                    sql = """
                        SELECT doctorGID FROM PatientGroup WHERE userId=%s
                    """
                    params = [user_id]
                    cursor.execute(sql, params)
                    doctor_gid = cursor.fetchone()[0]
                    if doctor_gid is None:
                        raise serializers.ValidationError(
                            "This patient doesn't have a doctor assigned."
                        )
                # If it is a doctor, then we allow him/her to login
                # ONLY if he/she is verified
                if role == "DOCTOR":
                    cursor.callproc("get_appuser_gid_role", [user_id])
                    doctor_gid = cursor.fetchone()[0]
                    if not check_doctor_is_verified(doctor_gid):
                        raise serializers.ValidationError(
                            "Your account hasn't been verified yet."
                        )
                # Select AuthToken for this user
                sql = """
                    SELECT token FROM AuthToken WHERE userId = %s
                """
                params = [user_id]
                cursor.execute(sql, params)
                token = cursor.fetchone()[0]
                if token is None:
                    raise serializers.ValidationError(
                        f"Somehow user {email} has no token assigned!"
                    )
                # Adding stuff to validated_data
                raw_data["role"] = role
                raw_data["token"] = token
        except (Exception, psycopg2.Error, serializers.ValidationError) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            raise ex
        return raw_data


class UpdateEmailSerializer(Serializer):
    email = serializers.EmailField(required=True, max_length=256)

    def update(self, request, validated_data):
        email = validated_data.get("email")
        try:
            user_id, token = get_userid_and_token(request)
            with connection.cursor() as cursor:
                cursor.callproc("update_appuser_email", [token, email])
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            return None
        Logger.write_message(
            "INFO", f"User id={user_id} successfully updated his/her email to {email}."
        )
        return {"success": f"You successfully changed email to {email} ."}


class UpdatePasswordSerializer(Serializer):
    old_password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )
    new_password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )
    confirmation_password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password]
    )

    def validate(self, raw_data):
        old_password = raw_data["old_password"]
        new_password = raw_data["new_password"]
        confirmation_password = raw_data["confirmation_password"]
        try:
            # Compare two new passwords
            if new_password != confirmation_password:
                raise serializers.ValidationError("New passwords don't match!")
            # Retrieve AppUser.id and his token from request
            user_id, token = get_userid_and_token(self.context["request"])
            # Get password hash of AppUser
            with connection.cursor() as cursor:
                sql = """
                    SELECT password FROM AppUser WHERE id = %s
                """
                params = [user_id]
                cursor.execute(sql, params)
                password_hash = cursor.fetchone()[0]
                # Compare raw old password to hash
                if not check_pass(old_password, password_hash):
                    raise serializers.ValidationError("Old password is incorrect.")
                # Append values to validated_data and change password to hashed
                raw_data["new_password"] = encrypt(new_password)
                raw_data.pop("confirmation_password")
                raw_data["user_id"] = user_id
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data

    def update(self, validated_data):
        user_id = validated_data.get("user_id")
        new_pass_hash = validated_data.get("new_password")
        try:
            with connection.cursor() as cursor:
                sql = """
                    UPDATE AppUser SET password = %s WHERE id = %s
                """
                params = [new_pass_hash, user_id]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        Logger.write_message(
            "INFO", f"User id={user_id} successfully updated his/her password."
        )
        return {"success": "You successfully changed your password."}


#
#
# USER SETTINGS
#
#


class ChangeMyAvatarSerialzier(Serializer):
    avatar = serializers.CharField(max_length=30, validators=[validate_avatar])

    def put(self, validated_data):
        avatar = validated_data.get("avatar")
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            with connection.cursor() as cursor:
                sql = """
                    UPDATE AppUser SET avatar = %s
                    WHERE id = %s
                """
                params = [avatar, user_id]
                cursor.execute(sql, params)
                data = {"success": "Successfully updated avatar.", "avatar": avatar}
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            return None
        return data


#
#
# ADMIN
#
#


class AdminGetUserGID_Role(Serializer):
    user_id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        user_id = validated_data["user_id"]
        try:
            with connection.cursor() as cursor:
                # Utilize get_appuser_gid_role PL/pgSQL function
                cursor.callproc("get_appuser_gid_role", [user_id])
                user_gid, role = cursor.fetchone()
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return {"id": user_id, "role": role, "gid": user_gid}

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminGetAllUsersInfo(Serializer):
    def get(self):
        try:
            with connection.cursor() as cursor:
                # Join everything we have about appusers
                sql = """
                    SELECT AppUser.id as user_id, AppUser.username as username,
                        AppUser.email as email,
                        AppUser.firstName || ' ' || AppUser.lastName as fullName,
                        AuthToken.token as token,
                        DoctorGroup.isVerified as isDoctorVerified,
                        DoctorGroup.occupation as doctorOccupation,
                        PatientGroup.doctorGID as relatedDoctorGID,
                        PatientGroup.dateOfPregnancy as patientDateOfPregnancy
                    FROM AppUser
                    JOIN AuthToken ON AppUser.id = AuthToken.userId
                    LEFT JOIN AdminGroup ON AppUser.id = AdminGroup.userId
                    LEFT JOIN PatientGroup ON AppUser.id = PatientGroup.userId
                    LEFT JOIN DoctorGroup ON AppUser.id = DoctorGroup.userId
                """
                params = []
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "user_id",
                        "username",
                        "email",
                        "fullName",
                        "token",
                        "isDoctorVerified",
                        "doctorOccupation",
                        "relatedDoctorGID",
                        "patientDateOfPregnancy",
                    ],
                    many=True,
                )
                # Add roles to each entry
                for i in range(len(data)):
                    user_id = data[i]["user_id"]
                    cursor.callproc("get_appuser_gid_role", [user_id])
                    gid, role = cursor.fetchone()
                    data[i]["role"] = role
                    data[i]["gid"] = gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_admin(self):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")


class AdminAssignDoctorSerializer(Serializer):
    patient_gid = serializers.IntegerField(validators=[MinValueValidator(1)])
    doctor_gid = serializers.IntegerField(validators=[MinValueValidator(1)])
    force = serializers.BooleanField(required=False)

    def assign_doctor(self, validated_data):
        patient_id = validated_data["patient_id"]
        patient_gid = validated_data["patient_gid"]
        doctor_gid = validated_data["doctor_gid"]
        changes_happened = False
        try:
            with connection.cursor() as cursor:
                # First, let's check if patient had doctor assigned before
                sql = """
                    SELECT doctorGID FROM PatientGroup WHERE id = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                before_doctor_gid = cursor.fetchone()[0]
                if before_doctor_gid is None:
                    # Create a new conversation
                    changes_happened = True
                    sql, params = sql_generate_qs_with_params_insert(
                        "Conversation", ["patientGID"], [patient_gid]
                    )
                    cursor.execute(sql, params)
                # Well, if turns out she had a doctor then
                # check if it's the same one
                elif before_doctor_gid != doctor_gid:
                    changes_happened = True
                    # Remove the old conversation
                    sql = """
                        DELETE FROM Conversation WHERE patientGID = %s
                    """
                    params = [patient_gid]
                    cursor.execute(sql, params)
                    # Remove the booked meetings
                    sql = """
                        DELETE FROM TimeSlot WHERE bookedByPatientGID = %s
                    """
                    params = [patient_gid]
                    cursor.execute(sql, params)
                    # Create a new conversation
                    sql, params = sql_generate_qs_with_params_insert(
                        "Conversation", ["patientGID"], [patient_gid]
                    )
                    cursor.execute(sql, params)
                # Assign the doctor
                sql = """
                    UPDATE PatientGroup SET doctorGID = %s WHERE userId = %s
                """
                params = [doctor_gid, patient_id]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        if changes_happened:
            Logger.write_message(
                "INFO",
                f"Patient with GID={patient_gid} has a new doctor assigned! "
                + "Doctor GID={doctor_gid}.",
            )
            return {"success": "New doctor has been successfully assigned."}
        return {"success": "No changes."}

    def validate(self, raw_data):
        patient_gid = raw_data["patient_gid"]
        doctor_gid = raw_data["doctor_gid"]
        force = raw_data.get("force", None)
        try:
            with connection.cursor() as cursor:
                user_id, token = get_userid_and_token(self.context["request"])
                # Validate admin
                if not check_role(user_id, "admin"):
                    raise PermissionDenied("You're not admin.")
                # Validate doctor
                sql = """
                    SELECT * FROM appuser_with_GIDs WHERE doctor_gid = %s
                """
                params = [doctor_gid]
                if not check_if_exists(sql, params):
                    raise serializers.ValidationError(
                        f"Doctor with GID={doctor_gid} not found."
                    )
                if not check_doctor_is_verified(doctor_gid):
                    raise serializers.ValidationError(
                        f"Doctor with GID={doctor_gid} is not verified."
                    )
                # Validate patient and get his AppUser.id
                sql = """
                    SELECT * FROM appuser_with_GIDs WHERE patient_gid = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                res = cursor.fetchone()
                if res is None:
                    raise serializers.ValidationError(
                        f"Patient with GID={patient_gid} not found."
                    )
                patient_id = res[0]  # AppUser.id
                sql = """
                    SELECT doctorGID FROM PatientGroup WHERE userId = %s
                """
                params = [patient_id]
                cursor.execute(sql, params)
                doctor_gid_assigned = cursor.fetchone()[0]
                # If doctor has already been assigned
                if doctor_gid_assigned is not None:
                    if force is None or not force:
                        raise serializers.ValidationError(
                            "This patient already has an assigned doctor."
                        )
                # Append values to validated_data
                # print(f"patient_id: {patient_id}")
                raw_data["patient_id"] = patient_id
                # print(f"raw_data after statement: {raw_data}")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        # print(f"raw_data after try except: {raw_data}")
        return raw_data


class AdminVerifyDoctorSerializer(Serializer):
    gid = serializers.IntegerField(validators=[MinValueValidator(1)])

    def verify(self, validated_data):
        gid = validated_data.get("gid")
        try:
            with connection.cursor() as cursor:
                sql = """
                    UPDATE doctorGroup SET isVerified = true
                    WHERE id = %s
                """
                params = [gid]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        Logger.write_message("INFO", f"Doctor with gid={gid} is now verified!")
        return {"success": "Doctor has been verified."}

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Doctor exists in database
            if not check_if_exists(
                "SELECT id FROM doctorGroup WHERE id = %s", [raw_data["gid"]]
            ):
                raise serializers.ValidationError(
                    f"Doctor with gid={raw_data['gid']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#
# MENU
#
#


class AdminPostMenuSerializer(Serializer):
    title = serializers.CharField(max_length=100)
    content = serializers.CharField()
    image = serializers.CharField(max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def create(self, validated_data):
        title = validated_data.get("title")
        content = validated_data.get("content")
        image = validated_data.get("image")
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_insert(
                    "Menu",
                    ["title", "content", "image", "category"],
                    [title, content, image, category],
                )
                cursor.execute(sql, params)
                # Retrieve just created data
                sql = """
                    SELECT id, title, content, image, category, publicationDate
                    FROM Menu ORDER BY id DESC LIMIT 1
                """
                params = []
                data = select_fields_to_json_response(
                    sql,
                    params,
                    ["id", "title", "content", "image", "category", "publicationDate"],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminUpdateMenuSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])
    title = serializers.CharField(required=False, max_length=100)
    content = serializers.CharField(required=False)
    image = serializers.CharField(required=False, max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def update(self, validated_data):
        _id = validated_data.get("_id")
        title = validated_data.get("title", UNSET)
        content = validated_data.get("content", UNSET)
        image = validated_data.get("image", UNSET)
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_update(
                    "Menu",
                    ["title", "content", "image", "category"],
                    [title, content, image, category],
                )
                sql += "WHERE id = %s"
                params.append(_id)
                cursor.execute(sql, params)
                # Retrieve updated data
                sql = """
                    SELECT id, title, content, image, category, publicationDate
                    FROM Menu WHERE id=%s
                """
                params = [_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    ["id", "title", "content", "image", "category", "publicationDate"],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Menu exists in database
            if not check_if_exists(
                "SELECT id FROM Menu WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Menu item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class GetListMenuSerializer(Serializer):
    def get(self):
        try:
            sql = """
                SELECT id, title, content, image, category, publicationDate
                FROM Menu ORDER BY id
            """
            params = []
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "title", "content", "image", "category", "publicationDate"],
                many=True,
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data


class GetDetailMenuSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        try:
            sql = """
                SELECT id, title, content, image, category, publicationDate
                FROM Menu WHERE id = %s
            """
            params = [validated_data["_id"]]
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "title", "content", "image", "category", "publicationDate"],
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            if not check_if_exists(
                "SELECT id FROM Menu WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Menu item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminDeleteMenuSerializer(Serializer):
    _id = _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def delete(self, validated_data):
        try:
            with connection.cursor() as cursor:
                sql = """
                    DELETE FROM Menu WHERE id = %s
                """
                params = [validated_data["_id"]]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return False
        return True

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Menu exists in database
            if not check_if_exists(
                "SELECT id FROM Menu WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Menu item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#
# EXERCISE
#
#


class AdminPostExerciseSerializer(Serializer):
    title = serializers.CharField(max_length=100)
    content = serializers.CharField()
    image = serializers.CharField(max_length=1000, allow_null=True)
    video = serializers.CharField(max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def create(self, validated_data):
        title = validated_data.get("title")
        content = validated_data.get("content")
        image = validated_data.get("image")
        video = validated_data.get("video")
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_insert(
                    "Exercise",
                    ["title", "content", "image", "video", "category"],
                    [title, content, image, video, category],
                )
                cursor.execute(sql, params)
                # Retrieve just created data
                sql = """
                    SELECT id, title, content, image, video, category, publicationDate
                    FROM Exercise ORDER BY id DESC LIMIT 1
                """
                params = []
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "id",
                        "title",
                        "content",
                        "image",
                        "video",
                        "category",
                        "publicationDate",
                    ],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminUpdateExerciseSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])
    title = serializers.CharField(required=False, max_length=100)
    content = serializers.CharField(required=False)
    image = serializers.CharField(required=False, max_length=1000, allow_null=True)
    video = serializers.CharField(required=False, max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def update(self, validated_data):
        _id = validated_data.get("_id")
        title = validated_data.get("title", UNSET)
        content = validated_data.get("content", UNSET)
        image = validated_data.get("image", UNSET)
        video = validated_data.get("video", UNSET)
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_update(
                    "Exercise",
                    ["title", "content", "image", "video", "category"],
                    [title, content, image, video, category],
                )
                sql += "WHERE id = %s"
                params.append(_id)
                cursor.execute(sql, params)
                # Retrieve just created data
                sql = """
                    SELECT id, title, content, image, video, category, publicationDate
                    FROM Exercise WHERE id = %s
                """
                params = [_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "id",
                        "title",
                        "content",
                        "image",
                        "video",
                        "category",
                        "publicationDate",
                    ],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Exercise exists in database
            if not check_if_exists(
                "SELECT id FROM Exercise WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Exercise item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class GetListExerciseSerializer(Serializer):
    def get(self):
        try:
            sql = """
                SELECT id, title, content, image, video, category, publicationDate
                FROM Exercise ORDER BY id
            """
            params = []
            data = select_fields_to_json_response(
                sql,
                params,
                [
                    "id",
                    "title",
                    "content",
                    "image",
                    "video",
                    "category",
                    "publicationDate",
                ],
                many=True,
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data


class GetDetailExerciseSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        try:
            sql = """
                SELECT id, title, content, image, video, category, publicationDate
                FROM Exercise WHERE id = %s
            """
            params = [validated_data["_id"]]
            data = select_fields_to_json_response(
                sql,
                params,
                [
                    "id",
                    "title",
                    "content",
                    "image",
                    "video",
                    "category",
                    "publicationDate",
                ],
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            if not check_if_exists(
                "SELECT id FROM Exercise WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Exercise item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminDeleteExerciseSerializer(Serializer):
    _id = _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def delete(self, validated_data):
        try:
            with connection.cursor() as cursor:
                sql = """
                    DELETE FROM Exercise WHERE id = %s
                """
                params = [validated_data["_id"]]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return False
        return True

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Exercise exists in database
            if not check_if_exists(
                "SELECT id FROM Exercise WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Exercise item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#
# ARTICLE
#
#


class AdminPostArticleSerializer(Serializer):
    title = serializers.CharField(max_length=100)
    content = serializers.CharField()
    image = serializers.CharField(max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def create(self, validated_data):
        title = validated_data.get("title")
        content = validated_data.get("content")
        image = validated_data.get("image")
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_insert(
                    "Article",
                    ["title", "content", "image", "category"],
                    [title, content, image, category],
                )
                cursor.execute(sql, params)
                # Retrieve just created data
                sql = """
                    SELECT id, title, content, image, category, publicationDate
                    FROM Article ORDER BY id DESC LIMIT 1
                """
                params = []
                data = select_fields_to_json_response(
                    sql,
                    params,
                    ["id", "title", "content", "image", "category", "publicationDate"],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminUpdateArticleSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])
    title = serializers.CharField(required=False, max_length=100)
    content = serializers.CharField(required=False)
    image = serializers.CharField(required=False, max_length=1000, allow_null=True)
    category = serializers.CharField(required=False, max_length=100, allow_null=True)

    def update(self, validated_data):
        _id = validated_data.get("_id")
        title = validated_data.get("title", UNSET)
        content = validated_data.get("content", UNSET)
        image = validated_data.get("image", UNSET)
        category = validated_data.get("category", UNSET)
        try:
            with connection.cursor() as cursor:
                sql, params = sql_generate_qs_with_params_update(
                    "Article",
                    ["title", "content", "image", "category"],
                    [title, content, image, category],
                )
                sql += "WHERE id = %s"
                params.append(_id)
                cursor.execute(sql, params)
                # Retrieve just created data
                sql = """
                    SELECT id, title, content, image, category, publicationDate
                    FROM Article WHERE id = %s
                """
                params = [_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    ["id", "title", "content", "image", "category", "publicationDate"],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Menu exists in database
            if not check_if_exists(
                "SELECT id FROM Article WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Article item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class GetListArticleSerializer(Serializer):
    def get(self):
        try:
            sql = """
                SELECT id, title, content, image, category, publicationDate
                FROM Article ORDER BY id
            """
            params = []
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "title", "content", "image", "category", "publicationDate"],
                many=True,
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data


class GetDetailArticleSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        try:
            sql = """
                SELECT id, title, content, image, category, publicationDate
                FROM Article WHERE id = %s
            """
            params = [validated_data["_id"]]
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "title", "content", "image", "category", "publicationDate"],
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            if not check_if_exists(
                "SELECT id FROM Article WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Article item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class AdminDeleteArticleSerializer(Serializer):
    _id = _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def delete(self, validated_data):
        try:
            with connection.cursor() as cursor:
                sql = """
                    DELETE FROM Article WHERE id = %s
                """
                params = [validated_data["_id"]]
                cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return False
        return True

    def validate(self, raw_data):
        try:
            admin_user_id, token = get_userid_and_token(self.context["request"])
            # Validate admin
            if not check_role(admin_user_id, "admin"):
                raise PermissionDenied("You're not admin.")
            # Validate Article exists in database
            if not check_if_exists(
                "SELECT id FROM Article WHERE id = %s", [raw_data["_id"]]
            ):
                raise serializers.ValidationError(
                    f"Article item with id={raw_data['_id']} doesn't exist."
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#
# CONVERSATIONS & MESSAGES
#
#


#
#   PATIENT SIDE
#


class PatientGetConversationSerialier(Serializer):
    def get(self):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            with connection.cursor() as cursor:
                data = select_fields_to_json_response(
                    """
                        SELECT employee_name, employee_occupation,
                            employee_profile_picture, unread_messages_count
                        FROM patient_get_conversation_info(%s)
                    """,
                    [patient_gid],
                    [
                        "employeeName",
                        "employeeOccupation",
                        "employeeProfilePicture",
                        "unreadMessagesCount",
                    ],
                )
                # Serialize all the messages from this conversation
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_patient_gid = %s
                    ORDER BY message_id
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                messages = []
                for record in res:
                    message_id = record[0]
                    params = [message_id]
                    message_info = select_fields_to_json_response(
                        sql,
                        params,
                        [
                            "id",
                            "content",
                            "fromName",
                            "fromPatient",
                            "readTime",
                            "time",
                        ],
                    )
                    messages.append(message_info)
                # print(messages)
                data["messages"] = messages
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
            return None
        return data


class PatientPostMessageSerializer(Serializer):
    content = serializers.CharField()

    def post(self, validated_data):
        content = validated_data.get("content")
        patient_gid = validated_data.get("patient_gid")
        try:
            with connection.cursor() as cursor:
                # Get Conversation id
                sql = """
                    SELECT id FROM Conversation WHERE patientGID = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                conversation_id = cursor.fetchone()[0]
                # Post Message to Conversation
                sql, params = sql_generate_qs_with_params_insert(
                    "Message",
                    ["conversationId", "content", "isFromPatient"],
                    [conversation_id, content, True],
                )
                cursor.execute(sql, params)
                # Get new Message id
                sql = """
                    SELECT id FROM Message WHERE conversationId = %s
                    ORDER BY id DESC LIMIT 1
                """
                params = [conversation_id]
                cursor.execute(sql, params)
                message_id = cursor.fetchone()[0]
                # Get message info
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                params = [message_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "id",
                        "content",
                        "fromName",
                        "fromPatient",
                        "readTime",
                        "time",
                    ],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientMarkAsReadSerializer(Serializer):
    def mark_as_read(self, validated_data):
        patient_gid = validated_data.get("patient_gid")
        try:
            with connection.cursor() as cursor:
                # Select all message ids that are unread by patient
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_patient_gid = %s
                        AND NOT message_is_read
                        AND NOT message_is_from_patient
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                unread_message_ids = tuple([rec[0] for rec in res])
                # Update all unread messages to read state
                local_datetime = unaware_to_local(datetime.now())
                print(f"Local datetime.now() with TZ: {local_datetime}")
                sql, params = sql_generate_qs_with_params_update(
                    "Message", ["readTime"], [local_datetime]
                )
                sql += "WHERE id IN %s"
                params.append(unread_message_ids)
                if not len(unread_message_ids) == 0:
                    cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return {"success": "Read all the doctor messages."}

    def check_valid_patient(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientGetUnreadMessagesSerializer(Serializer):
    def get_unread(self, validated_data):
        patient_gid = validated_data.get("patient_gid")
        try:
            with connection.cursor() as cursor:
                # Select all message ids that are unread by patient
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_patient_gid = %s
                        AND NOT message_is_read
                        AND NOT message_is_from_patient
                    ORDER BY message_id
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                # Read all of those messages into JSON
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                data = []
                for record in res:
                    message_id = record[0]
                    params = [message_id]
                    message_info = select_fields_to_json_response(
                        sql,
                        params,
                        [
                            "id",
                            "content",
                            "fromName",
                            "fromPatient",
                            "readTime",
                            "time",
                        ],
                    )
                    data.append(message_info)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_patient(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#   DOCTOR SIDE
#


class DoctorGetAllConversationsSerializer(Serializer):
    def get(self, validated_data):
        doctor_gid = validated_data.get("doctor_gid")
        try:
            with connection.cursor() as cursor:
                # Get all accessible conversation ids
                cursor.callproc("get_doctor_related_conversation_ids", [doctor_gid])
                conversation_ids = sorted([record[0] for record in cursor.fetchall()])
                data = []
                # Get info about each one of them
                for conv_id in conversation_ids:
                    sql = """
                        SELECT patient_name, patient_date_of_pregnancy,
                        patient_profile_picture, unread_messages_count
                        FROM doctor_get_conversation_info(%s)
                    """
                    params = [conv_id]
                    data_entry = select_fields_to_json_response(
                        sql,
                        params,
                        [
                            "patientName",
                            "patientDateOfPregnancy",
                            "patientProfilePicture",
                            "unreadMessagesCount",
                        ],
                    )
                    data_entry["id"] = conv_id
                    data.append(data_entry)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_doctor(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This doctor has not been verified yet."
                )
            # Append validated_data
            raw_data["doctor_gid"] = doctor_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class DoctorGetConversationSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        conversation_id = validated_data.get("_id")
        try:
            with connection.cursor() as cursor:
                # Get info about conversation
                sql = """
                    SELECT patient_name, patient_date_of_pregnancy,
                    patient_profile_picture, unread_messages_count
                    FROM doctor_get_conversation_info(%s)
                """
                params = [conversation_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "patientName",
                        "patientDateOfPregnancy",
                        "patientProfilePicture",
                        "unreadMessagesCount",
                    ],
                )
                data["id"] = conversation_id
                # Append with messages related to this conversation
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_id = %s
                    ORDER BY message_id
                """
                params = [conversation_id]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                messages = []
                for record in res:
                    message_id = record[0]
                    params = [message_id]
                    message_info = select_fields_to_json_response(
                        sql,
                        params,
                        [
                            "id",
                            "content",
                            "fromName",
                            "fromPatient",
                            "readTime",
                            "time",
                        ],
                    )
                    messages.append(message_info)
                data["messages"] = messages
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This doctor has not been verified yet."
                )
            # Validate conversation id
            with connection.cursor() as cursor:
                cursor.callproc("get_doctor_related_conversation_ids", [doctor_gid])
                conversation_ids = [record[0] for record in cursor.fetchall()]
                if raw_data["_id"] not in conversation_ids:
                    raise serializers.ValidationError(
                        f"Conversation id={raw_data['_id']} either does not exist"
                        + " or does not belong to you."
                    )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class DoctorGetUnreadMessagesSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        conversation_id = validated_data.get("_id")
        try:
            with connection.cursor() as cursor:
                # Get info about conversation
                sql = """
                    SELECT patient_name, patient_date_of_pregnancy,
                    patient_profile_picture, unread_messages_count
                    FROM doctor_get_conversation_info(%s)
                """
                params = [conversation_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "patientName",
                        "patientDateOfPregnancy",
                        "patientProfilePicture",
                        "unreadMessagesCount",
                    ],
                )
                data["id"] = conversation_id
                # Append with messages related to this conversation
                # which are unread by doctor
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_id = %s
                        AND NOT message_is_read
                        AND message_is_from_patient
                    ORDER BY message_id
                """
                params = [conversation_id]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                messages = []
                for record in res:
                    message_id = record[0]
                    params = [message_id]
                    message_info = select_fields_to_json_response(
                        sql,
                        params,
                        [
                            "id",
                            "content",
                            "fromName",
                            "fromPatient",
                            "readTime",
                            "time",
                        ],
                    )
                    messages.append(message_info)
                data["messages"] = messages
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This doctor has not been verified yet."
                )
            # Validate conversation id
            with connection.cursor() as cursor:
                cursor.callproc("get_doctor_related_conversation_ids", [doctor_gid])
                conversation_ids = [record[0] for record in cursor.fetchall()]
                if raw_data["_id"] not in conversation_ids:
                    raise serializers.ValidationError(
                        f"Conversation id={raw_data['_id']} either does not exist"
                        + " or does not belong to you."
                    )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class DoctorPostMessageSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])
    content = serializers.CharField()

    def post(self, validated_data):
        content = validated_data.get("content")
        conversation_id = validated_data.get("_id")
        try:
            with connection.cursor() as cursor:
                # Post Message to Conversation
                sql, params = sql_generate_qs_with_params_insert(
                    "Message",
                    ["conversationId", "content", "isFromPatient"],
                    [conversation_id, content, False],
                )
                cursor.execute(sql, params)
                # Get new Message id
                sql = """
                    SELECT id FROM Message WHERE conversationId = %s
                    ORDER BY id DESC LIMIT 1
                """
                params = [conversation_id]
                cursor.execute(sql, params)
                message_id = cursor.fetchone()[0]
                # Get message info
                sql = """
                    SELECT id, content, from_name, is_from_patient, read_time, time_posted
                    FROM get_message_info(%s)
                """
                params = [message_id]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    [
                        "id",
                        "content",
                        "fromName",
                        "fromPatient",
                        "readTime",
                        "time",
                    ],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This doctor has not been verified yet."
                )
            # Validate conversation id
            with connection.cursor() as cursor:
                cursor.callproc("get_doctor_related_conversation_ids", [doctor_gid])
                conversation_ids = [record[0] for record in cursor.fetchall()]
                if raw_data["_id"] not in conversation_ids:
                    raise serializers.ValidationError(
                        f"Conversation id={raw_data['_id']} either does not exist"
                        + " or does not belong to you."
                    )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class DoctorMarkAsReadSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def mark_as_read(self, validated_data):
        conversation_id = validated_data.get("_id")
        try:
            with connection.cursor() as cursor:
                # Select all message ids that are unread by doctor
                sql = """
                    SELECT message_id FROM conversation_message_view
                    WHERE conversation_id = %s
                        AND NOT message_is_read
                        AND message_is_from_patient
                """
                params = [conversation_id]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                unread_message_ids = tuple([rec[0] for rec in res])
                # Update all unread messages to read state
                local_datetime = unaware_to_local(datetime.now())
                print(f"Local datetime.now() with TZ: {local_datetime}")
                sql, params = sql_generate_qs_with_params_update(
                    "Message", ["readTime"], [local_datetime]
                )
                sql += "WHERE id IN %s"
                params.append(unread_message_ids)
                if not len(unread_message_ids) == 0:
                    cursor.execute(sql, params)
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return {"success": "Read all the doctor messages."}

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This doctor has not been verified yet."
                )
            # Validate conversation id
            with connection.cursor() as cursor:
                cursor.callproc("get_doctor_related_conversation_ids", [doctor_gid])
                conversation_ids = [record[0] for record in cursor.fetchall()]
                if raw_data["_id"] not in conversation_ids:
                    raise serializers.ValidationError(
                        f"Conversation id={raw_data['_id']} either does not exist"
                        + " or does not belong to you."
                    )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


#
#
# VIDEO MEETNGS & BOOKING
#
#


#
#   PATIENT SIDE
#
class PatientGetBookedMeetingsSerializer(Serializer):
    def get(self, validated_data):
        patient_gid = validated_data.get("patient_gid")
        for_today = self.context["request"].GET.get("today", False)
        if for_today is not False:
            for_today = bool(for_today.lower() == "true")
        try:
            sql = """
                SELECT *
                FROM get_booked_meetings(%s, %s, %s)
                ORDER BY booking_time
            """
            params = [True, patient_gid, for_today]
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "timeslotId", "dateTime", "enabled", "title"],
                many=True,
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_patient(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientBookNewMeetingSerializer(Serializer):
    date_time = serializers.DateTimeField(
        input_formats=["%Y-%m-%d'T'%H:%M:%SZ"], validators=[validate_booking_datetime]
    )

    def post(self, validated_data):
        patient_gid = validated_data.get("patient_gid")
        booking_time = validated_data.get("date_time")
        print(booking_time)
        try:
            with connection.cursor() as cursor:
                # Prefetch doctorGID
                sql = """
                    SELECT doctorGID FROM PatientGroup
                    WHERE id = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                doctor_gid = cursor.fetchone()[0]
                # Book a meeting
                # booking_time_str = prepare_datetime_str_for_sql(booking_time)
                sql = (
                    "INSERT INTO TimeSlot (bookingTime, doctorGID, bookedByPatientGID) "
                    + "VALUES (%s, %s, %s)"
                )

                params = [booking_time, doctor_gid, patient_gid]
                cursor.execute(sql, params)
                # Get id of TimeSlot
                sql = """
                    SELECT id FROM TimeSlot
                    ORDER BY id DESC LIMIT 1
                """
                params = []
                cursor.execute(sql, params)
                timeslot_id = cursor.fetchone()[0]

                # Now create VideoMeeting
                roomName = generate_token("roomname")
                sql = """
                    INSERT INTO VideoMeeting (roomName, timeslotId)
                    VALUES (%s, %s)
                """
                params = [roomName, timeslot_id]
                cursor.execute(sql, params)
                # Retrieve timeslot patient just booked
                sql = """
                    SELECT id, timeslot_id, booking_time,
                        _enabled, title
                    FROM get_booked_meetings(%s, %s, %s)
                    ORDER BY id DESC LIMIT 1
                """
                params = [True, patient_gid, False]
                data = select_fields_to_json_response(
                    sql,
                    params,
                    ["id", "timeslotId", "dateTime", "enabled", "title"],
                )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Check if timeslot is open
            booking_time = raw_data.get("date_time")
            if not check_can_patient_book_meeting(patient_gid, booking_time):
                raise serializers.ValidationError(
                    "Cannot book a meeting on this time. Sorry."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientGetAvailableTimeSlotsSerializer(Serializer):
    def get(self, validated_data):
        patient_gid = validated_data.get("patient_gid")
        try:
            with connection.cursor() as cursor:
                # Prefetch doctorGID
                sql = """
                    SELECT doctorGID FROM PatientGroup
                    WHERE id = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                doctor_gid = cursor.fetchone()[0]
                # Select all doctor's booked meetins
                sql = """
                    SELECT booking_time
                    FROM get_booked_meetings(%s, %s, %s)
                    ORDER BY booking_time
                """
                params = [False, doctor_gid, False]
                cursor.execute(sql, params)
                res = cursor.fetchall()
                booked_datetimes = [utc_to_local(r[0]) for r in res]
                # Start the magic
                local_datetime = unaware_to_local(datetime.now())
                # print(local_datetime)
                date_start = local_datetime.date()
                # print(date_start)
                start_time = unaware_to_local(
                    datetime(
                        year=date_start.year,
                        month=date_start.month,
                        day=date_start.day,
                        hour=10,
                    )
                )
                end_date = date_start + timedelta(days=14)
                end_time = unaware_to_local(
                    datetime(
                        year=end_date.year,
                        month=end_date.month,
                        day=end_date.day,
                        hour=18,
                    )
                )
                curr_time = start_time
                data = []
                delta = timedelta(hours=1)
                data_part = {
                    "date": start_time.strftime("%Y-%m-%d"),
                    "dateTimes": [],
                }
                while curr_time != end_time:
                    if curr_time not in booked_datetimes:
                        data_part["dateTimes"].append(
                            curr_time.strftime("%Y-%m-%d'T'%H:%M:%SZ")
                        )
                    if curr_time.hour < 18:
                        curr_time += delta
                    else:
                        curr_time += timedelta(hours=16)
                        if len(data_part["dateTimes"]) != 0:
                            data.append(data_part)
                        data_part = {
                            "date": curr_time.strftime("%Y-%m-%d"),
                            "dateTimes": [],
                        }
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_patient(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientGetMeetingTokenSerializer(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        _id = validated_data.get("_id")
        patient_gid = validated_data.get("patient_gid")
        try:
            with connection.cursor() as cursor:
                # Get patient email
                sql = """
                    SELECT AppUser.email
                    FROM AppUser
                    JOIN PatientGroup ON AppUser.id = PatientGroup.userId
                    WHERE PatientGroup.id = %s
                """
                params = [patient_gid]
                cursor.execute(sql, params)
                email = cursor.fetchone()[0]
                # Get room name
                sql = """
                    SELECT room_name FROM videomeeting_info_view
                    WHERE videomeeting_id = %s AND patient_gid = %s
                """
                params = [_id, patient_gid]
                cursor.execute(sql, params)
                roomName = cursor.fetchone()[0]
                token = generate_twilio_videoroom_token(roomName, email)
                data = {"accessToken": token}
        except (Exception, psycopg2.Error) as ex:
            print(ex)
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "PATIENT"):
                raise PermissionDenied("You're not a patient.")
            patient_gid = get_appuser_gid_role(user_id)[0]
            if not check_patient_is_allowed_to_login(patient_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Check if meeting exists and belongs to patient
            _id = raw_data.get("_id")
            with connection.cursor() as cursor:
                sql = """
                    SELECT videomeeting_id FROM videomeeting_info_view
                    WHERE videomeeting_id = %s AND patient_gid = %s
                """
                params = [_id, patient_gid]
                cursor.execute(sql, params)
                res = cursor.fetchone()
                if res is None:
                    raise serializers.ValidationError("No such meeting for you.")
            # Append validated_data
            raw_data["patient_gid"] = patient_gid
        except (Exception, psycopg2.Error) as ex:
            print(ex)
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class PatientCancelMeetingSerializer(Serializer):
    pass


#
#   DOCTOR SIDE
#


class DoctorGetBookedMeetings(Serializer):
    def get(self, validated_data):
        doctor_gid = validated_data.get("doctor_gid")
        for_today = self.context["request"].GET.get("today", False)
        if for_today is not False:
            for_today = bool(for_today.lower() == "true")
        try:
            sql = """
                SELECT *
                FROM get_booked_meetings(%s, %s, %s)
                ORDER BY booking_time
            """
            params = [False, doctor_gid, for_today]
            data = select_fields_to_json_response(
                sql,
                params,
                ["id", "timeslotId", "dateTime", "enabled", "title"],
                many=True,
            )
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def check_valid_doctor(self):
        raw_data = {}
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate patient
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Append validated_data
            raw_data["doctor_gid"] = doctor_gid
        except (Exception, psycopg2.Error) as ex:
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data


class DoctorGetMeetingToken(Serializer):
    _id = serializers.IntegerField(validators=[MinValueValidator(1)])

    def get(self, validated_data):
        _id = validated_data.get("_id")
        doctor_gid = validated_data.get("doctor_gid")
        try:
            with connection.cursor() as cursor:
                # Get patient email
                sql = """
                    SELECT AppUser.email
                    FROM AppUser
                    JOIN DoctorGroup ON AppUser.id = DoctorGroup.userId
                    WHERE DoctorGroup.id = %s
                """
                params = [doctor_gid]
                cursor.execute(sql, params)
                email = cursor.fetchone()[0]
                # Get room name
                sql = """
                    SELECT room_name FROM videomeeting_info_view
                    WHERE videomeeting_id = %s AND doctor_gid = %s
                """
                params = [_id, doctor_gid]
                cursor.execute(sql, params)
                roomName = cursor.fetchone()[0]
                token = generate_twilio_videoroom_token(roomName, email)
                data = {"accessToken": token}
        except (Exception, psycopg2.Error) as ex:
            print(ex)
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            return None
        return data

    def validate(self, raw_data):
        try:
            user_id, token = get_userid_and_token(self.context["request"])
            # Validate doctor
            if not check_role(user_id, "DOCTOR"):
                raise PermissionDenied("You're not a doctor.")
            doctor_gid = get_appuser_gid_role(user_id)[0]
            if not check_doctor_is_verified(doctor_gid):
                raise serializers.ValidationError(
                    "This patient doesn't have a doctor assigned."
                )
            # Check if meeting exists and belongs to doctor
            _id = raw_data.get("_id")
            with connection.cursor() as cursor:
                sql = """
                    SELECT videomeeting_id FROM videomeeting_info_view
                    WHERE videomeeting_id = %s AND doctor_gid = %s
                """
                params = [_id, doctor_gid]
                cursor.execute(sql, params)
                res = cursor.fetchone()
                if res is None:
                    raise serializers.ValidationError("No such meeting for you.")
            # Append validated_data
            raw_data["doctor_gid"] = doctor_gid
        except (Exception, psycopg2.Error) as ex:
            print(ex)
            Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
            if isinstance(ex, PermissionDenied):
                raise ex
            if isinstance(ex, psycopg2.Error):
                raise serializers.ValidationError("Database error occured.")
            if isinstance(ex, serializers.ValidationError):
                raise ex
            raise serializers.ValidationError("Bad request.")
        return raw_data
