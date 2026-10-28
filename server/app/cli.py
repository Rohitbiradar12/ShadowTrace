"""Admin commands until the dashboard exists.

python -m app.cli create-enrollment-token --hours 24 --max-uses 1
python -m app.cli list-devices
python -m app.cli verify-chain dev_0123456789abcdef
"""

import argparse
import asyncio
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.core.db import init_db
from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
from app.forensics.verify import verify_device_chain
from app.models import Device, EnrollmentToken


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


async def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    token = sub.add_parser("create-enrollment-token")
    token.add_argument("--hours", type=float, default=24)
    token.add_argument("--max-uses", type=int, default=1)
    token.add_argument("--note")
    sub.add_parser("list-devices")
    verify = sub.add_parser("verify-chain")
    verify.add_argument("device_id")
    args = parser.parse_args()

    client = await init_db(get_settings())
    try:
        match args.command:
            case "create-enrollment-token":
                await create_enrollment_token(args.hours, args.max_uses, args.note)
            case "list-devices":
                await list_devices()
            case "verify-chain":
                return await verify_chain(args.device_id)
        return 0
    finally:
        await client.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
