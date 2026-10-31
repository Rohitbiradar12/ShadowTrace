from app.models.alert import Alert, AlertHit
from app.models.command import Command
from app.models.device import Device
from app.models.enrollment import EnrollmentToken
from app.models.event import Event
from app.models.notification import Notification
from app.models.telegram import TelegramAction, TelegramCursor
from app.models.user import AuditEntry, LoginBucket, Session, User

DOCUMENT_MODELS = [
    Device,
    EnrollmentToken,
    Event,
    Alert,
    AlertHit,
    Notification,
    Command,
    User,
    Session,
    LoginBucket,
    AuditEntry,
    TelegramAction,
    TelegramCursor,
]

__all__ = [
    "DOCUMENT_MODELS",
    "Device",
    "EnrollmentToken",
    "Event",
    "Alert",
    "AlertHit",
    "Notification",
    "Command",
    "User",
    "Session",
    "LoginBucket",
    "AuditEntry",
]
