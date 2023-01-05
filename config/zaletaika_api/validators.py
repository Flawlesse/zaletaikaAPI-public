import re

from rest_framework.serializers import ValidationError


def validate_latitude(value):
    if value < -90 or value > 90:
        raise ValidationError(
            {"latitude": "Latitude is supposed to be between -90 and 90."}
        )


def validate_longitude(value):
    if value < -180 or value > 180:
        raise ValidationError(
            {"longitude": "Longitude is supposed to be between -180 and 180."}
        )


def validate_avatar(value):
    if value not in ("BROWN_HAIR", "BLOND_HAIR", "DARK_SKIN", "RED_HAIR", "HIJAB"):
        raise ValidationError("Avatar wasn't chosen correctly.")


def validate_regrole(value):
    if value not in ("PATIENT", "DOCTOR"):
        raise ValidationError(
            "Role is supposed to be either of these: PATIENT, DOCTOR."
        )


def validate_booking_datetime(value):
    if (
        value.hour < 10
        or value.hour > 18
        or value.minute != 0
        or value.second != 0
        or value.microsecond != 0
    ):
        raise ValidationError("Invalid booking datetime given.")


def validate_password(password):
    if len(password) < 8 or len(password) > 40:
        raise ValidationError(
            "The password must be at least 8 symbols long and 40 symbols long at max."
        )
    if not re.findall(r"[A-Z]", password):
        raise ValidationError(
            "The password must contain at least 1 uppercase letter, A-Z."
        )
    if not re.findall(r"[a-z]", password):
        raise ValidationError(
            "The password must contain at least 1 lowercase letter, a-z."
        )
    if not re.findall(r"\d", password):
        raise ValidationError("The password must contain at least 1 digit, 0-9.")
    if not re.findall(r"[()\[\]{}|\\`~!@#$%^&*_\-+=;:'\",<>.?]", password):
        raise ValidationError(
            "The password must contain at least 1 special character: "
            + r"()[]{}|`~!@#$%^&*_-+=;:'\",<>.?"
        )
    if re.findall(r"\s", password):
        raise ValidationError("The password must not contain any space characters")
