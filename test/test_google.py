import asyncio
import aiohttp_proxy_aware as aiohttp


def test_google():
    async def async_test():
        async with aiohttp.ClientSession() as session:
            async with session.get("https://www.google.com") as r:
                t = await r.text()

    asyncio.get_event_loop().run_until_complete(async_test())
