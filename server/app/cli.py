"""Local administration, account recovery and forensic verification commands.

python -m app.cli create-enrollment-token --hours 24 --max-uses 1
python -m app.cli list-devices
python -m app.cli verify-chain dev_0123456789abcdef
"""

import argparse
import asyncio
import getpass
import json
import sys
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.core.db import init_db
from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
from app.detection.engine import get_engine
from app.detection.service import detect_device
from app.forensics.verify import verify_device_chain
from app.models import Alert, Command, Device, EnrollmentToken, Notification
from app.models.user import AuditEntry, Session, User
from app.services.auth import PASSWORDS, create_user, validate_password
from app.services.commands import cancel_command, queue_command


async def create_enrollment_token(hours: float, max_uses: int, note: str | None) -> None:
    token = generate_token(ENROLLMENT_TOKEN_PREFIX)
    expires_at = datetime.now(UTC) + timedelta(hours=hours)
    await EnrollmentToken(
        token_hash=hash_token(token), expires_at=expires_at, max_uses=max_uses, note=note
    ).insert()
    print(token)
    print(f"(valid until {expires_at:%Y-%m-%d %H:%M} UTC, {max_uses} use(s), shown only once)")


async def list_devices() -> None:
    devices = await Device.find_all().sort(+Device.hostname).to_list()
    if not devices:
        print("No devices enrolled.")
    for d in devices:
        seen = f"{d.last_seen:%Y-%m-%d %H:%M:%S}" if d.last_seen else "never"
        print(f"{d.device_id}  {d.hostname:<24} {d.os:<8} events={d.chain_length:<8} seen={seen}")


async def verify_chain(device_id: str) -> int:
    device = await Device.find_one(Device.device_id == device_id)
    if device is None:
        print(f"Unknown device {device_id}")
        return 1
    result = await verify_device_chain(device)
    if result.ok:
        print(f"OK - {result.checked} events verified, chain intact.")
        return 0
    print(f"TAMPERING DETECTED at chain index {result.broken_at_index}: {result.reason}")
    return 2


async def list_alerts(limit: int, device_id: str | None = None) -> None:
    query = {"device_id": device_id} if device_id else {}
    alerts = await Alert.find(query).sort(-Alert.last_seen).limit(limit).to_list()
    if not alerts:
        print("No alerts.")
    for alert in alerts:
        print(
            f"{alert.alert_id}  {alert.severity:<8} {alert.rule_id:<16} "
            f"{alert.device_id} count={alert.occurrence_count} {alert.title}"
        )


async def show_alert(alert_id: str) -> int:
    alert = await Alert.find_one(Alert.alert_id == alert_id)
    if alert is None:
        print("Unknown alert")
        return 1
    notifications = await Notification.find(Notification.alert_id == alert_id).to_list()
    print(
        json.dumps(
            {
                "alert": alert.model_dump(mode="json", exclude={"id"}),
                "notifications": [n.model_dump(mode="json", exclude={"id"}) for n in notifications],
            },
            indent=2,
        )
    )
    return 0


async def list_notifications(limit: int) -> None:
    jobs = await Notification.find_all().sort(-Notification.created_at).limit(limit).to_list()
    if not jobs:
        print("No notifications.")
    for job in jobs:
        print(
            f"{job.notification_id} {job.status:<12} attempts={job.attempts} {job.last_error or ''}"
        )


async def retry_notification(notification_id: str) -> int:
    result = await Notification.get_pymongo_collection().update_one(
        {
            "notification_id": notification_id,
            "status": {"$in": ["failed", "unconfigured", "disabled"]},
        },
        {
            "$set": {
                "status": "pending",
                "attempts": 0,
                "next_attempt_at": datetime.now(UTC),
                "lease_until": None,
                "last_error": None,
            }
        },
    )
    print(
        "Queued for retry."
        if result.modified_count
        else "No failed or disabled notification found."
    )
    return 0 if result.modified_count else 1


async def scan_pending() -> int:
    total = 0
    async for device in Device.find_all():
        while processed := await detect_device(device.device_id):
            total += processed
    print(f"Processed {total} pending event(s).")
    return 0


async def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    token = sub.add_parser("create-enrollment-token")
    token.add_argument("--hours", type=float, default=24)
    token.add_argument("--max-uses", type=int, default=1)
    token.add_argument("--note")
    user = sub.add_parser("create-user", help="create a dashboard account (no default password)")
    user.add_argument("username")
    user.add_argument("--role", choices=["admin", "analyst", "viewer"], default="viewer")
    user.add_argument("--password-stdin", action="store_true")
    reset = sub.add_parser("reset-password", help="replace a user's password and revoke sessions")
    reset.add_argument("username")
    reset.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list-devices")
    sub.add_parser("validate-rules")
    sub.add_parser("scan-pending")
    alerts = sub.add_parser("list-alerts")
    alerts.add_argument("--device")
    alerts.add_argument("--limit", type=int, default=20)
    detail = sub.add_parser("show-alert")
    detail.add_argument("alert_id")
    notifications = sub.add_parser("list-notifications")
    notifications.add_argument("--limit", type=int, default=20)
    commands = sub.add_parser("list-commands")
    commands.add_argument("--device")
    commands.add_argument("--limit", type=int, default=20)
    command_detail = sub.add_parser("show-command")
    command_detail.add_argument("command_id")
    cancel = sub.add_parser("cancel-command", help="cancel a command that has not been delivered")
    cancel.add_argument("command_id")
    issue = sub.add_parser("issue-command")
    issue.add_argument("device_id")
    issue.add_argument("action", choices=["lock_workstation", "kill_process"])
    issue.add_argument("--event", help="process_started event UUID; required for kill_process")
    issue.add_argument("--reason", required=True)
    issue.add_argument("--ttl", type=int, default=120, help="expiry in seconds (10..900)")
    retry = sub.add_parser("retry-notification")
    retry.add_argument("notification_id")
    verify = sub.add_parser("verify-chain")
    verify.add_argument("device_id")
    args = parser.parse_args()

    if args.command == "validate-rules":
        engine = get_engine()
        print(
            f"OK - {len(engine.rules)} enabled rules; "
            f"{len(engine.intel.definitions)} indicator lists."
        )
        return 0

    client = await init_db(get_settings())
    try:
        match args.command:
            case "create-user" | "reset-password":
                password = (
                    sys.stdin.readline().rstrip("\r\n")
                    if args.password_stdin
                    else getpass.getpass("Password (12+ characters): ")
                )
                if not args.password_stdin and getpass.getpass("Confirm password: ") != password:
                    print("Passwords do not match.")
                    return 1
                try:
                    validate_password(password)
                    actor = f"cli:{getpass.getuser()}"
                    if args.command == "create-user":
                        await create_user(args.username, password, args.role, actor)
                        print(f"Created {args.username} ({args.role}).")
                    else:
                        user = await User.find_one(User.username == args.username.strip().lower())
                        if user is None:
                            raise ValueError("User not found")
                        await User.get_pymongo_collection().update_one(
                            {"_id": user.id},
                            {
                                "$set": {
                                    "password_hash": await asyncio.to_thread(
                                        PASSWORDS.hash, password
                                    )
                                },
                                "$inc": {"session_version": 1},
                            },
                        )
                        await Session.find(Session.username == user.username).delete()
                        await AuditEntry(
                            actor=actor, action="password_reset", target=user.username
                        ).insert()
                        print("Password reset; existing sessions revoked.")
                except ValueError as exc:
                    print(str(exc))
                    return 1
            case "create-enrollment-token":
                await create_enrollment_token(args.hours, args.max_uses, args.note)
            case "list-devices":
                await list_devices()
            case "verify-chain":
                return await verify_chain(args.device_id)
            case "list-alerts":
                await list_alerts(max(1, min(args.limit, 1000)), args.device)
            case "show-alert":
                return await show_alert(args.alert_id)
            case "list-notifications":
                await list_notifications(max(1, min(args.limit, 1000)))
            case "retry-notification":
                return await retry_notification(args.notification_id)
            case "scan-pending":
                return await scan_pending()
            case "issue-command":
                try:
                    command = await queue_command(
                        args.device_id,
                        args.action,
                        actor=f"cli:{getpass.getuser()}",
                        reason=args.reason,
                        event_id=args.event,
                        ttl_seconds=args.ttl,
                    )
                except ValueError as exc:
                    print(f"Command rejected: {exc}")
                    return 1
                print(f"Queued {command.command_id}; expires {command.expires_at.isoformat()}")
            case "list-commands":
                query = {"device_id": args.device} if args.device else {}
                commands = (
                    await Command.find(query)
                    .sort(-Command.created_at)
                    .limit(max(1, min(args.limit, 1000)))
                    .to_list()
                )
                for command in commands:
                    print(
                        f"{command.command_id} {command.device_id} "
                        f"{command.action:<18} {command.status:<10} {command.actor}"
                    )
                if not commands:
                    print("No commands.")
            case "show-command":
                command = await Command.find_one(Command.command_id == args.command_id)
                if command is None:
                    print("Unknown command")
                    return 1
                print(json.dumps(command.model_dump(mode="json", exclude={"id"}), indent=2))
            case "cancel-command":
                cancelled = await cancel_command(args.command_id, f"cli:{getpass.getuser()}")
                print(
                    "Cancelled." if cancelled else "Command is not pending; cannot cancel delivery."
                )
                return 0 if cancelled else 1
        return 0
    finally:
        await client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
