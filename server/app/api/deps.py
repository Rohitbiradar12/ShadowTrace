from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from app.core.security import hash_token
from app.models import Device


async def get_device(x_device_key: Annotated[str, Header()]) -> Device:
    device = await Device.find_one(Device.api_key_hash == hash_token(x_device_key))
    if device is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked device key")
    return device


CurrentDevice = Annotated[Device, Depends(get_device)]
