import base64
import hashlib
import logging
import socket
import struct

import pywintypes
import sspi
import sspicon
import win32security

# import his, even though not directly used, to get the dependency captured by Pyinstaller
# this fixed 'No module named 'win32timezone'' errors
import win32timezone

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

_logger = logging.getLogger(__name__)


async def get_proxy_auth_header_sspi(session, proxy_url, peercert=None, delegate=False, host=None):
    """Performs a GET request against the proxy server to start and complete an NTLM authentication process
    
    Invoke this after getting a 407 error.  Returns the proxy_headers to use going forwards (in dict format)
    
    Overview of the protocol/exchange: https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a

    Inspired by: https://github.com/brandond/requests-negotiate-sspi/blob/master/requests_negotiate_sspi/requests_negotiate_sspi.py
    (But this is async, and it's for proxy auth not normal www auth)
    """
    scheme = 'NTLM'

    host = None
    if host is None:
        targeturl = urlparse(proxy_url)
        host = targeturl.hostname
        try:
            host = socket.getaddrinfo(host, None, 0, 0, 0, socket.AI_CANONNAME)[0][3]
        except socket.gaierror as e:
            _logger.error('Skipping canonicalization of name %s due to error: %s', host, e)

    targetspn = '{}/{}'.format("HTTP", host)

    # Set up SSPI connection structure
    pkg_info = win32security.QuerySecurityPackageInfo(scheme)
    clientauth = sspi.ClientAuth(scheme, targetspn=targetspn)  # , auth_info=self._auth_info)
    sec_buffer = win32security.PySecBufferDescType()

    # Calling sspi.ClientAuth with scflags set requires you to specify all the flags, including defaults.
    # We just want to add ISC_REQ_DELEGATE.
    # if delegate:
    #    clientauth.scflags |= sspicon.ISC_REQ_DELEGATE

    # Channel Binding Hash (aka Extended Protection for Authentication)
    # If this is a SSL connection, we need to hash the peer certificate, prepend the RFC5929 channel binding type,
    # and stuff it into a SEC_CHANNEL_BINDINGS structure.
    # This should be sent along in the initial handshake or Kerberos auth will fail.
    if peercert is not None:
        md = hashlib.sha256()
        md.update(peercert)
        appdata = 'tls-server-end-point:'.encode('ASCII') + md.digest()
        cbtbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_CHANNEL_BINDINGS)
        cbtbuf.Buffer = struct.pack('LLLLLLLL{}s'.format(len(appdata)), 0, 0, 0, 0, 0, 0, len(appdata), 32, appdata)
        sec_buffer.append(cbtbuf)

    # content_length = int(response.request.headers.get('Content-Length', '0'), base=10)

    # if hasattr(response.request.body, 'seek'):
    #    if content_length > 0:
    #        response.request.body.seek(-content_length, 1)
    #    else:
    #        response.request.body.seek(0, 0)

    # Consume content and release the original connection
    # to allow our new request to reuse the same one.
    # response.content
    # response.raw.release_conn()
    # request = response.request.copy()

    # this is important for some web applications that store
    # authentication-related info in cookies
    # if response.headers.get('set-cookie'):
    #    request.headers['Cookie'] = response.headers.get('set-cookie')

    # Send initial challenge auth header
    try:
        error, auth = clientauth.authorize(sec_buffer)
        headers = {'Proxy-Authorization': f'{scheme} {base64.b64encode(auth[0].Buffer).decode("ASCII")}'}
        response2 = await session.get(proxy_url, headers=headers)

        _logger.debug('Got response: ' + str(response2))
        # Sending Initial Context Token - error={} authenticated={}'.format(error, clientauth.authenticated))
    except pywintypes.error as e:
        _logger.warning('Error calling {}: {}'.format(e[1], e[2]), exc_info=e)
        raise

    # https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a

    # expect to get 407 error and proxy-authenticate header
    if response2.status != 407:
        raise Exception(f'Expected 407, got {response2.status} status code')

    # Extract challenge message from server
    challenge = [val[len(scheme) + 1:] for val in response2.headers.get('proxy-Authenticate', '').split(', ') if
                 scheme in val]
    if len(challenge) != 1:
        raise Exception('Did not get exactly one {} challenge from server.'.format(scheme))

    # Add challenge to security buffer
    tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
    tokenbuf.Buffer = base64.b64decode(challenge[0])
    sec_buffer.append(tokenbuf)
    _logger.debug('Got Challenge Token (NTLM)')

    # Perform next authorization step 
    try:
        error, auth = clientauth.authorize(sec_buffer)
        headers = {'proxy-Authorization': '{} {}'.format(scheme, base64.b64encode(auth[0].Buffer).decode('ASCII'))}
        _logger.debug(str(headers))
    except pywintypes.error as e:
        _logger.error('Error calling {}: {}'.format(e[1], e[2]), exc_info=e)
        raise

    return headers
