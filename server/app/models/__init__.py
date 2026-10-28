from app.models.device import Device
from app.models.enrollment import EnrollmentToken
from app.models.event import Event

DOCUMENT_MODELS = [Device, EnrollmentToken, Event]

__all__ = ["DOCUMENT_MODELS", "Device", "EnrollmentToken", "Event"]
