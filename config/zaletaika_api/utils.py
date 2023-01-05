import random
import string
import traceback
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import psycopg2
import pytz
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db import connection
from passlib.handlers.pbkdf2 import pbkdf2_sha256
from rest_framework import serializers
from rest_framework.views import exception_handler
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant

local_tz = pytz.timezone(settings.TIME_ZONE)  # use your local timezone name here
UNSET = -1  # Flag that determines optional fields


def utc_to_local(utc_dt) -> datetime:
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_tz.normalize(local_dt)  # .normalize might be unnecessary


def unaware_to_local(dt) -> datetime:
    return dt.replace(tzinfo=ZoneInfo(settings.TIME_ZONE))


#
#
# LOGGER
#
#


class LoggerException(Exception):
    pass


class Logger:
    @staticmethod
    def write_message(_type: str, msg: str, stacktrace: str = None):
        if _type not in ("INFO", "WARN", "ERR", "FATAL"):
            raise LoggerException("Invalid message type for logger.")
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO Logs (type, message, stackTrace) VALUES (%s, %s, %s)",
                [_type, msg, stacktrace],
            )


#
#
# PASSWORD MANAGEMENT
#
#


def encrypt(password) -> str:
    "Returns encrypted string for given password."
    return pbkdf2_sha256.encrypt(
        password,
        rounds=26000,
        salt_size=32,
    )


def check_pass(raw, enc_string) -> bool:
    "Checks the raw password against encrypted string."
    return pbkdf2_sha256.verify(raw, enc_string)


#
#
# HELPFUL DB-RELATED FUNCTIONS
#
#


def generate_token(username: str):
    """Generate a random token for an AppUser."""
    return "".join(
        random.choices(string.digits + string.ascii_letters, k=32)
        + ["".join(random.sample(username, len(username)))[:36]]
        + random.choices(string.digits + string.ascii_letters, k=32)
    )


def get_userid_and_token(request):
    """Retrieve token from request headers, return BOTH the token itself
    and the AppUser.id that utilizes it."""
    try:
        with connection.cursor() as cursor:
            # Just utilize the stored PL/pgSQL function
            token = request.META.get("HTTP_AUTHORIZATION", None)
            if token is not None:
                token_parts = str(token).split()
                if token_parts[0] != "Token":
                    raise PermissionDenied(
                        f"Invalid Authorization header prefix '{token_parts[0]}'. "
                        + "The only acceptable is 'Token'."
                    )
                if len(token_parts) == 1:
                    raise PermissionDenied("No token was passed.")
            else:
                raise PermissionDenied("Authorization header was not given!")
            # At this point, token_parts[1] is our correct token
            token = token_parts[1]
            cursor.callproc("get_userid_by_token", [token])
            user_id = cursor.fetchone()[0]
            return user_id, token
    except (Exception, psycopg2.Error, serializers.ValidationError) as ex:
        Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
        raise ex


def check_role(user_id: int, role: str) -> bool:
    """Checks whether this AppUser is of needed role."""
    role = role.upper()
    try:
        with connection.cursor() as cursor:
            cursor.callproc("get_appuser_gid_role", [user_id])
            actual_role = cursor.fetchone()[1]
            return actual_role == role
    except (Exception, psycopg2.Error) as ex:
        Logger.write_message("ERR", str(ex), stacktrace=traceback.format_exc())
        return False


def check_if_exists(sql_select_stmt: str, params: list) -> bool:
    """Checks if entry is present in database. Basically, Django-ORM's .exists() method."""
    assert sql_select_stmt.strip().upper().startswith("SELECT")
    with connection.cursor() as cursor:
        cursor.execute(sql_select_stmt, params)
        res = cursor.fetchone()
    return res is not None


def check_doctor_is_verified(doctor_gid: int) -> bool:
    with connection.cursor() as cursor:
        cursor.callproc("is_doctor_verified", [doctor_gid])
        res = cursor.fetchone()[0]
    return res


def check_patient_is_allowed_to_login(patient_gid: int) -> bool:
    with connection.cursor() as cursor:
        cursor.callproc("is_patient_allowed_to_login", [patient_gid])
        res = cursor.fetchone()[0]
    return res


def check_can_patient_book_meeting(patient_gid: int, booking_time_passed: datetime):
    """
    Checks if patient can book a meeting on a certain time.
    """
    with connection.cursor() as cursor:
        print("booking_time_passed=", booking_time_passed)
        print("patient_gid=", patient_gid)
        cursor.callproc(
            "can_patient_book_meeting",
            [patient_gid, booking_time_passed, "Python"],
        )
        # emulating callproc
        # sql = f"SELECT * FROM can_patient_book_meeting(%s, {booking_time_passed}, %s)"
        # params = [patient_gid, "Python"]
        # cursor.execute(sql, params)
        res = cursor.fetchone()
        print("result=", res)
    return res[0]


def get_appuser_gid_role(user_id: int):
    with connection.cursor() as cursor:
        cursor.callproc("get_appuser_gid_role", [user_id])
        patient_gid, role = cursor.fetchone()
    return patient_gid, role


#
#
# Raw SQL generation
#
#
# def prepare_datetime_str_for_sql(date_time: datetime) -> str:
#     """
#     Generate PostgreSQL-valid string to pass right into
#     SQL statement, with NO escaping. Timezone is 'Europe/Minsk'
#     Example: "timestamptz '2022-12-19 19:00:00 +3'"
#     This is a fix for strange Django behavior regarding timezones.
#     """
#     dt_string = (date_time - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")
#     result = f"timestamptz '{dt_string} +3'"
#     return result


def sql_generate_qs_with_params_insert(
    table_name: str, column_names: list, column_values: list
):
    """Given the table name, table column names & their corresponding values,
    generate a python-tolerant SQL INSERT statement with the 'params'."""
    assert len(column_names) != 0
    assert len(column_names) == len(column_values)
    assert isinstance(table_name, str)
    assert all([isinstance(name, str) for name in column_names])
    assert all([name.strip() != "" for name in column_names])
    assert any([val != UNSET for val in column_values])
    col_names = []
    col_vals = []
    for name, val in list(zip(column_names, column_values)):
        if val is not UNSET:
            col_names.append(name)
            col_vals.append(val)
    querystring = f"""
        INSERT INTO {table_name} ({', '.join(col_names)})
        VALUES ({', '.join(['%s' for _ in col_vals])})
    """
    return querystring, col_vals


def sql_generate_qs_with_params_update(
    table_name: str, column_names: list, column_values: list
):
    """Given the table name, table column names & their corresponding values,
    generate a python-tolerant SQL UPDATE statement with the 'params'.
    !!! Note that you're supposed to append the querystring and params
    due to WHERE statement absence."""
    assert len(column_names) != 0
    assert len(column_names) == len(column_values)
    assert isinstance(table_name, str)
    assert all([isinstance(name, str) for name in column_names])
    assert all([name.strip() != "" for name in column_names])
    assert any([val != UNSET for val in column_values])
    col_names = []
    col_vals = []
    for name, val in list(zip(column_names, column_values)):
        if val is not UNSET:
            col_names.append(name)
            col_vals.append(val)
    querystring = f"""
        UPDATE {table_name}
        SET {', '.join([ f'{name} = %s' for name in col_names])} """
    return querystring, col_vals


#
#
# JSON from SELECT
#
#


def select_fields_to_json_response(
    sql_select_stmt: str, params: list, json_names: list, many=False
):
    """Given the SELECT statement, transform result into a dictionary or list of dictionaries.
    !!! Pay attention that json_names are supposed to be in the same order as in the
    SELECT statement passed to this function, otherwise return value is undefined."""
    assert isinstance(many, bool)
    assert len(json_names) != 0
    assert isinstance(sql_select_stmt, str)
    assert sql_select_stmt.strip().upper().startswith("SELECT")
    assert all([isinstance(name, str) for name in json_names])
    assert all([name.strip() != "" for name in json_names])

    with connection.cursor() as cursor:
        cursor.execute(sql_select_stmt, params)
        if many:
            res = cursor.fetchall()
            # print(res)
            # print(sql_select_stmt)
        else:
            res = cursor.fetchone()
    if not many:
        data = {}
        for i, col_name in enumerate(json_names):
            data_part = res[i]
            if isinstance(data_part, datetime):
                # In this case, convert to string with TZ=Europe/Minsk.

                # For some weird reason, django.db.connection is not
                # behaving the same way as psycopg2.connection does.
                # If you try to pull the timestamp with time zone
                # using django's connection, the datetime object
                # will be corrected against UTC timezone.
                # That means, -3 hours from actual Minsk time.

                # print(data_part.utcoffset() is None)
                # print(data_part.utcoffset() == timedelta())
                # print(data_part.utcoffset())
                # print(type(data_part.utcoffset()))
                if (
                    data_part.utcoffset() is None
                    or data_part.utcoffset() == timedelta()
                ):
                    data_part = utc_to_local(data_part)
                timestring = data_part.strftime("%Y-%m-%d'T'%H:%M:%SZ")
                data[col_name] = timestring
            else:
                data[col_name] = res[i]
        return data
    data = []
    for res_entry in res:
        data_entry = {}
        for i, col_name in enumerate(json_names):
            data_part = res_entry[i]
            if isinstance(data_part, datetime):
                if (
                    data_part.utcoffset() is None
                    or data_part.utcoffset() == timedelta()
                ):
                    data_part = utc_to_local(data_part)
                timestring = data_part.strftime("%Y-%m-%d'T'%H:%M:%SZ")
                data_entry[col_name] = timestring
            else:
                data_entry[col_name] = res_entry[i]
        data.append(data_entry)
    return data


#
#
# TWILIO
#
#
def generate_twilio_videoroom_token(roomName: str, email: str):
    """
    Generate Access Token based on email as identity,
    grant the Video Grant to Room with specified roomName
    to that token and spit it back to the appuser.
    """
    assert roomName.strip() != ""
    assert email.strip() != ""
    token = AccessToken(
        settings.TWILIO_ACCOUNT_SID,
        settings.TWILIO_API_KEY_SID,
        settings.TWILIO_API_KEY_SECRET,
        identity=email,
    )
    token.add_grant(VideoGrant(room=roomName))
    return token.to_jwt()


#
#
# FORGOT PASSWORD FLOW
#
#


class ResetCodeManager:
    __ttl = timedelta(minutes=2)

    @classmethod
    def get_or_create_code(cls, email: str) -> str:
        key = email + "__code"
        code = cache.get(key, None)
        if code is not None:
            return code
        code = "".join(random.choices(string.digits, k=4))
        cache.add(key, code, timeout=cls.__ttl.seconds)
        return cache.get(key)

    @classmethod
    def try_use_code(cls, email: str, code: str) -> bool:
        key = email + "__code"
        if cache.get(key) != code:
            return False
        cache.delete(key)
        return True


class SessionTokenManager:
    __ttl = timedelta(minutes=10)

    @classmethod
    def get_or_create_token(cls, email: str) -> str:
        key = email + "__token"
        token = cache.get(key, None)
        if token is not None:
            return token
        token = "".join(random.choices(string.digits + string.ascii_letters, k=32))
        cache.add(key, token, timeout=cls.__ttl.seconds)
        return cache.get(key)

    @classmethod
    def try_use_token(cls, email: str, token: str) -> bool:
        key = email + "__token"
        if cache.get(key) != token:
            return False
        cache.delete(key)
        return True


#
#
# OTHER STUFF
#
#


def convert_data_to_geojson(data):
    transformed_data = {}
    if data.get("latitude") is not None and data.get("longitude") is not None:
        latitude, longitude = (
            data.pop("latitude"),
            data.pop("longitude"),
        )
        # According to WKT standard is: POINT (x y), or POINT (Lon Lat)
        transformed_data["geometry"] = {
            "type": "Point",
            "coordinates": [
                longitude,
                latitude,
            ],
        }
    properties = {**data}
    transformed_data["type"] = "Feature"
    transformed_data["properties"] = properties
    return transformed_data


def custom_exception_handler(exc, context):
    """Custom Django exception handler."""
    newdata = dict()
    newdata["errors"] = []

    def get_list_from_errors(data):
        to_return = []
        if not isinstance(data, (list, dict)):
            to_return.append(data)
        elif isinstance(data, list):
            for err in data:
                to_return.extend(get_list_from_errors(err))
        elif isinstance(data, dict):
            for err in data.values():
                to_return.extend(get_list_from_errors(err))
        return to_return

    response = exception_handler(exc, context)
    if response is not None:
        newdata["errors"].extend(get_list_from_errors(response.data))
        newdata["old_repr"] = response.data
        response.data = newdata
    return response
