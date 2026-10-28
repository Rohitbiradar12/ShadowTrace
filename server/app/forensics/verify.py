from app.forensics.chain import ChainVerification, verify_chain
from app.models import Device, Event


async def verify_device_chain(device: Device) -> ChainVerification:
    # Read raw documents so verification sees exactly what is stored, not a re-validated model.
    cursor = Event.get_pymongo_collection().find(
        {"device_id": device.device_id}, sort=[("chain_index", 1)]
    )
    events = [doc async for doc in cursor]
    return verify_chain(events, device.chain_length, device.chain_head)
