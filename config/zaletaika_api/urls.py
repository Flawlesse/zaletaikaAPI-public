from django.urls import path

from zaletaika_api.views import (
    DoctorConversationViewSet,
    PatientConversationViewSet,
    PatientMeetingViewSet,
    admin_assign_doctor_to_patient,
    admin_delete_article,
    admin_delete_exercise,
    admin_delete_menu,
    admin_get_all_users_info,
    admin_get_user_gid_and_role,
    admin_post_article,
    admin_post_exercise,
    admin_post_menu,
    admin_update_article,
    admin_update_exercise,
    admin_update_menu,
    admin_verify_doctor_by_gid,
    change_my_avatar,
    change_my_email,
    change_my_password,
    doctor_conversation_get_all_conversations,
    doctor_conversation_get_unread_messages,
    doctor_get_meeting_token,
    get_all_articles,
    get_all_exercises,
    get_all_menus,
    get_article_by_id,
    get_doctor_meetings,
    get_exercise_by_id,
    get_menu_by_id,
    login,
    patient_cancel_meeting,
    patient_conversation_get_unread_messages,
    patient_get_available_timeslots,
    patient_get_meeting_token,
    signup,
    testview,
)

# path(
#     "auth/reset-password/",
#     ForgotPasswordViewSet.as_view(
#         {
#             "get": "send_email",
#             "post": "send_reset_code",
#             "patch": "change_password",
#         }
#     ),
#     name="reset-password",
# ),
# #
# #
# # USER PROFILE
# #
# #
# path(
#     "user/",
#     UserInfoViewSet.as_view(
#         {
#             "get": "get_current",
#             "patch": "partial_update_current",
#             "delete": "delete_current",
#         }
#     ),
#     name="user_settings",
# ),  # NI

urlpatterns = [
    path("auth/testview/", testview, name="testview"),
    #
    #
    # AUTH PART
    #
    #
    path("auth/signup/", signup, name="signup"),
    path("auth/login/", login, name="login"),
    path("auth/change-email/", change_my_email, name="change_email"),
    path("auth/change-password/", change_my_password, name="change_password"),
    #
    #
    # UserSettings
    #
    #
    path("ella-avatar/", change_my_avatar, name="change_my_avatar"),
    #
    #
    # ADMIN
    #
    #
    path(
        "admin/get-user-gid-and-role/<int:pk>/",
        admin_get_user_gid_and_role,
        name="admin_get_user_gid_and_role",
    ),
    path(
        "admin/get-all-users-info/",
        admin_get_all_users_info,
        name="admin_get_all_users_info",
    ),
    path(
        "admin/verify-doctor-account/<int:pk>/",
        admin_verify_doctor_by_gid,
        name="admin_verify_doctor_by_gid",
    ),
    path(
        "admin/assign-doctor-to-patient/",
        admin_assign_doctor_to_patient,
        name="assign_doctor_to_patient",
    ),
    #
    #
    # MENU
    #
    #
    path("admin/menu/", admin_post_menu, name="admin_post_menu"),
    path("admin/menu/<int:pk>/", admin_update_menu, name="admin_update_menu"),
    path(
        "admin/menu/<int:pk>/delete/",
        admin_delete_menu,
        name="admin_delete_menu",
    ),
    path("menu/", get_all_menus, name="get_all_menus"),
    path("menu/<int:pk>/", get_menu_by_id, name="get_menu_by_id"),
    #
    #
    # EXERCISE
    #
    #
    path("admin/exercise/", admin_post_exercise, name="admin_post_exercise"),
    path(
        "admin/exercise/<int:pk>/", admin_update_exercise, name="admin_update_exercise"
    ),
    path(
        "admin/exercise/<int:pk>/delete/",
        admin_delete_exercise,
        name="admin_delete_exercise",
    ),
    path("exercise/", get_all_exercises, name="get_all_exercises"),
    path("exercise/<int:pk>/", get_exercise_by_id, name="get_exercise_by_id"),
    #
    #
    # ARTICLE
    #
    #
    path("admin/article/", admin_post_article, name="admin_post_article"),
    path("admin/article/<int:pk>/", admin_update_article, name="admin_update_article"),
    path(
        "admin/article/<int:pk>/delete/",
        admin_delete_article,
        name="admin_delete_article",
    ),
    path("article/", get_all_articles, name="get_all_articles"),
    path("article/<int:pk>/", get_article_by_id, name="get_article_by_id"),
    #
    #
    # MESSAGE AND CONVERSATION
    #
    #   Patient side
    path(
        "patient/conversation/",
        PatientConversationViewSet.as_view(
            {"get": "get_conversation", "post": "post_message"}
        ),
        name="patient_conversation_post_get",
    ),
    path(
        "patient/conversation/mark-as-read/",
        PatientConversationViewSet.as_view({"put": "mark_as_read"}),
    ),
    path(
        "patient/conversation/unread-messages/",
        patient_conversation_get_unread_messages,
        name="patient_conversation_get_unread_messages",
    ),
    #   Doctor side
    path(
        "doctor/conversations/",
        doctor_conversation_get_all_conversations,
        name="doctor_conversation_get_all_conversations",
    ),
    path(
        "doctor/conversations/<int:pk>/",
        DoctorConversationViewSet.as_view(
            {"get": "get_conversation", "post": "post_message"}
        ),
        name="patient_conversation_post_get",
    ),
    path(
        "doctor/conversations/<int:pk>/mark-as-read/",
        DoctorConversationViewSet.as_view({"put": "mark_as_read"}),
    ),
    path(
        "doctor/conversations/<int:pk>/unread-messages/",
        doctor_conversation_get_unread_messages,
        name="patient_conversation_get_unread_messages",
    ),
    #
    #
    # VIDEOMEETINGS & TIMESLOTS
    #
    #   Patient side
    path(
        "patient/meetings/",
        PatientMeetingViewSet.as_view(
            {
                "get": "get_booked_meetings",
                "post": "book_new_meeting",
            }
        ),
    ),
    path(
        "patient/meetings/<int:pk>/token/",
        patient_get_meeting_token,
        name="patient_get_meeting_token",
    ),
    path(
        "patient/meetings/available-time-slots/",
        patient_get_available_timeslots,
        name="patient_get_available_timeslots",
    ),
    path(
        "patient/meetings/<int:pk>/cancel/",
        patient_cancel_meeting,
        name="patient_cancel_meeting",
    ),  # NI
    #   Doctor side
    path("doctor/meetings/", get_doctor_meetings, name="get_doctor_meetings"),
    path(
        "doctor/meetings/<int:pk>/token/",
        doctor_get_meeting_token,
        name="doctor_get_meeting_token",
    ),
]
