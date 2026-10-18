"""Test cleanup compatible with the declared redis-py 5.0 client minimum."""


async def close_async_redis(client):
    closer = getattr(client, "aclose", None) or client.close
    await closer()
