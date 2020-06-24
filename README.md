# aiohttp-proxy-aware

The aiohttp library has support for proxies but you have to manually provide the settings.

This library provides a transparent wrapper that will allow you to use aiohttp without having to 
worry about manually setting up proxy data or authentication, just like any normal desktop browser 
like Chrome, IE, etc

## Installation

```
pip install git+https://github.com/moodysanalytics/aiohttp-proxy-aware.git
```

## Usage 

Instead of importing aiohttp, import aiohttp_proxy_aware.  You can use an alias to make it fully 
transparent
```
import asyncio
import aiohttp_proxy_aware as aiohttp
```
Then, use aiohttp as you would normally
```
async def get_google_homepage():
    async with aiohttp.ClientSession() as session:
        async with session.get("https://www.google.com") as r:
            t = await r.text()
```
