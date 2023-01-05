# import zoneinfo
from datetime import datetime

# import pytz
# from django.utils import timezone
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from zaletaika_api.serializers import (
    AdminAssignDoctorSerializer,
    AdminDeleteArticleSerializer,
    AdminDeleteExerciseSerializer,
    AdminDeleteMenuSerializer,
    AdminGetAllUsersInfo,
    AdminGetUserGID_Role,
    AdminPostArticleSerializer,
    AdminPostExerciseSerializer,
    AdminPostMenuSerializer,
    AdminUpdateArticleSerializer,
    AdminUpdateExerciseSerializer,
    AdminUpdateMenuSerializer,
    AdminVerifyDoctorSerializer,
    ChangeMyAvatarSerialzier,
    DoctorGetAllConversationsSerializer,
    DoctorGetBookedMeetings,
    DoctorGetConversationSerializer,
    DoctorGetMeetingToken,
    DoctorGetUnreadMessagesSerializer,
    DoctorMarkAsReadSerializer,
    DoctorPostMessageSerializer,
    GetDetailArticleSerializer,
    GetDetailExerciseSerializer,
    GetDetailMenuSerializer,
    GetListArticleSerializer,
    GetListExerciseSerializer,
    GetListMenuSerializer,
    LoginUserSerializer,
    PatientBookNewMeetingSerializer,
    PatientGetAvailableTimeSlotsSerializer,
    PatientGetBookedMeetingsSerializer,
    PatientGetConversationSerialier,
    PatientGetMeetingTokenSerializer,
    PatientGetUnreadMessagesSerializer,
    PatientMarkAsReadSerializer,
    PatientPostMessageSerializer,
    RegisterUserSerializer,
    UpdateEmailSerializer,
    UpdatePasswordSerializer,
)
from zaletaika_api.utils import (  # , utc_to_local
    generate_twilio_videoroom_token,
    unaware_to_local,
)


@api_view(["GET", "POST", "PUT", "PATCH", "DELETE"])
def testview(request):
    data = {}
    # now_dt = timezone.now()
    # print(f"timezone.now()={now_dt}")
    # # convert to a different time zone
    # actual_dt = utc_to_local(now_dt)
    # print(f"aware UTC timezone.now()={actual_dt}")
    local_datetime = unaware_to_local(datetime.now())
    print(f"Local datetime.now() with TZ: {local_datetime}")
    print(request.data)
    roomName = request.data.get("room_name")
    email = request.data.get("email")
    videoroom_token = generate_twilio_videoroom_token(roomName, email)
    data["accessToken"] = videoroom_token
    return Response(data, status=200)


@api_view(["PUT"])
def change_my_avatar(request):
    serializer = ChangeMyAvatarSerialzier(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.put(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# AUTH LOGIC
#
#


@api_view(["POST"])
def signup(request):
    serializer = RegisterUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    token = serializer.create(validated_data)
    if token is not None:
        return Response({"token": token}, status=201)
    return Response({"errors": ["Bad request."]}, 400)


@api_view(["POST"])
def login(request):
    serializer = LoginUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.perform_login(validated_data)
    return Response(response_data, status=200)


@api_view(["POST"])
def change_my_email(request):
    serializer = UpdateEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.update(request, validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["POST"])
def change_my_password(request):
    serializer = UpdatePasswordSerializer(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.update(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# ADMIN
#
#


@api_view(["GET"])
def admin_get_user_gid_and_role(request, pk):
    data = {"user_id": pk}
    serializer = AdminGetUserGID_Role(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["GET"])
def admin_get_all_users_info(request):
    serializer = AdminGetAllUsersInfo(context={"request": request})
    serializer.check_valid_admin()
    response_data = serializer.get()
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["POST"])
def admin_assign_doctor_to_patient(request):
    serializer = AdminAssignDoctorSerializer(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.assign_doctor(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["POST"])
def admin_verify_doctor_by_gid(request, pk):
    data = {"gid": pk}
    serializer = AdminVerifyDoctorSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.verify(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# MENU
#
#


@api_view(["POST"])
def admin_post_menu(request):
    data = request.data
    serializer = AdminPostMenuSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.create(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=201)


@api_view(["PATCH"])
def admin_update_menu(request, pk):
    data = {"_id": pk, **request.data}
    serializer = AdminUpdateMenuSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.update(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["DELETE"])
def admin_delete_menu(request, pk):
    data = {"_id": pk}
    serializer = AdminDeleteMenuSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    is_success = serializer.delete(validated_data)
    if not is_success:
        return Response({"errors": "Bad request."}, status=400)
    return Response({"success": f"Successfully deleted Menu id={pk}"}, status=204)


@api_view(["GET"])
def get_all_menus(request):
    serializer = GetListMenuSerializer()
    response_data = serializer.get()
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["GET"])
def get_menu_by_id(request, pk):
    data = {"_id": pk}
    serializer = GetDetailMenuSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# EXERICSE
#
#


@api_view(["POST"])
def admin_post_exercise(request):
    data = request.data
    serializer = AdminPostExerciseSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.create(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=201)


@api_view(["PATCH"])
def admin_update_exercise(request, pk):
    data = {"_id": pk, **request.data}
    serializer = AdminUpdateExerciseSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.update(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["DELETE"])
def admin_delete_exercise(request, pk):
    data = {"_id": pk}
    serializer = AdminDeleteExerciseSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    is_success = serializer.delete(validated_data)
    if not is_success:
        return Response({"errors": "Bad request."}, status=400)
    return Response({"success": f"Successfully deleted Exercise id={pk}"}, status=204)


@api_view(["GET"])
def get_all_exercises(request):
    serializer = GetListExerciseSerializer()
    response_data = serializer.get()
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["GET"])
def get_exercise_by_id(request, pk):
    data = {"_id": pk}
    serializer = GetDetailExerciseSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# ARTICLE
#
#


@api_view(["POST"])
def admin_post_article(request):
    data = request.data
    serializer = AdminPostArticleSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.create(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=201)


@api_view(["PATCH"])
def admin_update_article(request, pk):
    data = {"_id": pk, **request.data}
    serializer = AdminUpdateArticleSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.update(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["DELETE"])
def admin_delete_article(request, pk):
    data = {"_id": pk}
    serializer = AdminDeleteArticleSerializer(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    is_success = serializer.delete(validated_data)
    if not is_success:
        return Response({"errors": "Bad request."}, status=400)
    return Response({"success": f"Successfully deleted Article id={pk}"}, status=204)


@api_view(["GET"])
def get_all_articles(request):
    serializer = GetListArticleSerializer()
    response_data = serializer.get()
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["GET"])
def get_article_by_id(request, pk):
    data = {"_id": pk}
    serializer = GetDetailArticleSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#
# CONVERSATION & MESSAGE
#
#

#
#   PATIENT
#
class PatientConversationViewSet(GenericViewSet):
    @action(methods=["GET"], detail=False)
    def get_conversation(self, request):
        serializer = PatientGetConversationSerialier(context={"request": request})
        response_data = serializer.get()
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)

    @action(methods=["POST"], detail=False)
    def post_message(self, request):
        serializer = PatientPostMessageSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        response_data = serializer.post(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)

    @action(methods=["PUT"], detail=False)
    def mark_as_read(self, request):
        serializer = PatientMarkAsReadSerializer(context={"request": request})
        validated_data = serializer.check_valid_patient()
        response_data = serializer.mark_as_read(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)


@api_view(["GET"])
def patient_conversation_get_unread_messages(request):
    serializer = PatientGetUnreadMessagesSerializer(context={"request": request})
    validated_data = serializer.check_valid_patient()
    response_data = serializer.get_unread(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


#
#   DOCTOR
#
@api_view(["GET"])
def doctor_conversation_get_all_conversations(request):
    serializer = DoctorGetAllConversationsSerializer(context={"request": request})
    validated_data = serializer.check_valid_doctor()
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


@api_view(["GET"])
def doctor_conversation_get_unread_messages(request, pk):
    data = {"_id": pk}
    serializer = DoctorGetUnreadMessagesSerializer(
        data=data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, status=200)


class DoctorConversationViewSet(GenericViewSet):
    @action(methods=["GET"], detail=True)
    def get_conversation(self, request, pk=None):
        data = {"_id": pk}
        serializer = DoctorGetConversationSerializer(
            data=data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        response_data = serializer.get(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)

    @action(methods=["POST"], detail=True)
    def post_message(self, request, pk=None):
        data = {"_id": pk, **request.data}
        serializer = DoctorPostMessageSerializer(
            data=data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        response_data = serializer.post(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)

    @action(methods=["PUT"], detail=True)
    def mark_as_read(self, request, pk=None):
        data = {"_id": pk}
        serializer = DoctorMarkAsReadSerializer(data=data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        response_data = serializer.mark_as_read(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)


#
#
# VIDEOMEETINGS & TIMESLOTS
#
#

#
#   PATIENT
#
class PatientMeetingViewSet(GenericViewSet):
    @action(methods=["GET"], detail=False)
    def get_booked_meetings(self, request):
        serializer = PatientGetBookedMeetingsSerializer(context={"request": request})
        validated_data = serializer.check_valid_patient()
        response_data = serializer.get(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, status=200)

    @action(methods=["POST"], detail=False)
    def book_new_meeting(self, request):
        serializer = PatientBookNewMeetingSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        response_data = serializer.post(validated_data)
        if response_data is None:
            return Response({"errors": "Bad request."}, status=400)
        return Response(response_data, 200)


@api_view(["GET"])
def patient_get_meeting_token(request, pk):
    data = {"_id": pk}
    serializer = PatientGetMeetingTokenSerializer(
        data=data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, 200)


@api_view(["GET"])
def patient_get_available_timeslots(request):
    serializer = PatientGetAvailableTimeSlotsSerializer(context={"request": request})
    validated_data = serializer.check_valid_patient()
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, 200)


@api_view(["PUT"])
def patient_cancel_meeting(request, pk):
    pass


#
#   DOCTOR
#
@api_view(["GET"])
def get_doctor_meetings(request):
    serializer = DoctorGetBookedMeetings(context={"request": request})
    validated_data = serializer.check_valid_doctor()
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, 200)


@api_view(["GET"])
def doctor_get_meeting_token(request, pk):
    data = {"_id": pk}
    serializer = DoctorGetMeetingToken(data=data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    validated_data = serializer.validated_data
    response_data = serializer.get(validated_data)
    if response_data is None:
        return Response({"errors": "Bad request."}, status=400)
    return Response(response_data, 200)
