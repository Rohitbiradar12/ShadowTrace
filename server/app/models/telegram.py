from datetime import datetime
from typing import Annotated, Literal

from beanie import Document, Indexed


class TelegramAction(Document):
    key: Annotated[str, Indexed(unique=True)]
    callback_id: Annotated[str, Indexed(unique=True)]
    chat_id: str
    alert_id: str
    device_id: str
    event_id: str | None = None
    action: Literal["acknowledge", "lock_workstation", "kill_process"]
    label: str
    expires_at: datetime
    confirm_user_id: int | None = None
    confirm_until: datetime | None = None
    result: str | None = None
    used_at: datetime | None = None

    class Settings:
        name = "telegram_actions"


class TelegramCursor(Document):
    bot_key: Annotated[str, Indexed(unique=True)]
    offset: int = 0

    class Settings:
        name = "telegram_cursors"
