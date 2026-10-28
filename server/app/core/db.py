from beanie import init_beanie
from pymongo import AsyncMongoClient

from app.core.config import Settings
from app.models import DOCUMENT_MODELS


async def init_db(settings: Settings) -> AsyncMongoClient:
    # tz_aware so datetimes read back from Mongo compare correctly with aware UTC values.
    client: AsyncMongoClient = AsyncMongoClient(settings.mongo_url, tz_aware=True)
    await init_beanie(database=client[settings.mongo_db], document_models=DOCUMENT_MODELS)
    return client
