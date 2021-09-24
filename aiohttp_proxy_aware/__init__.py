# from aiohttp import ClientSession as _ClientSession
import aiohttp
import pypac
import logging
import asyncio
import os
import warnings

# bring through the entire aiohttp namespace
from aiohttp import *

logger = logging.getLogger(__name__)

# Prevent the "subclassing is discouraged" warning
# There is extensive discussion online about this and the author of aiohttp is stuck on the idea that subclassing
# should be discouraged
# https://github.com/aio-libs/aiohttp/issues/2691
# https://github.com/aio-libs/aiohttp/issues/3185
# The alternative (aggregation) requires reproducing the entire ClientSession /
# RequestManager api and making pass through functions.  If anything, this creates more dependencies on the current
# API and so I politely disagree with the aiohttp author.  We will ensure that a *specific* version of
# aiohttp is referenced as a dependency by this package in order to prevent surprises.
warnings.filterwarnings(
    action='ignore',
    category=DeprecationWarning,
    message="Inheritance class ClientSession from ClientSession is discouraged"
)


class ClientSession(aiohttp.ClientSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.pac = pypac.get_pac()
        self.resolver = pypac.resolver.ProxyResolver(
            self.pac) if self.pac else None
        logger.debug(f'pypac proxy detection result: {self.resolver}')

        self.proxy_auths = {}
        self.proxy_auth_lock = asyncio.Lock()

    async def _request(self, method, url, *args, **kwargs):
        if self.resolver:
            proxies = self.resolver.get_proxy_for_requests(url)
            proxy = proxies.get('http') if url.startswith(
                'http:') else proxies.get('https')
            logger.debug(f'proxy for {url}: {proxy}')
            kwargs['proxy'] = proxy
            if proxy in self.proxy_auths:
                kwargs['proxy_headers'] = self.proxy_auths[proxy]

        try:
            return await super()._request(method, url, *args, **kwargs)
        except ClientHttpProxyError as e:
            # traceback.print_exc()
            if e.status == 407 and os.name == 'nt':
                if proxy in self.proxy_auths:
                    # already tried.. try the request again in case another thread obtained auth while this request was
                    # processing
                    pass
                else:
                    async with self.proxy_auth_lock:
                        # after locking, check that another thread didn't do it
                        if proxy not in self.proxy_auths:
                            logger.debug(
                                "Proxy 407 error occurred - starting proxy NTLM auth negotiation"
                            )
                            import aiohttp_proxy_aware.sspi_auth
                            self.proxy_auths[
                                proxy] = await aiohttp_proxy_aware.sspi_auth.get_proxy_auth_header_sspi(
                                    self, proxy)

                # try again
                kwargs['proxy_headers'] = self.proxy_auths[proxy]
                return await super()._request(method, url, *args, **kwargs)
