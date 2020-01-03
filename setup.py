from distutils.core import setup

setup(
    name='aio-proxy-aware',
    version='0.1.1',
    packages=['aiohttp_proxy_aware',],
    long_description="Wrapper for aiohttp that automatically deals with proxies, including SSPI/NTLM authentication on "
                     "Windows",
    #package_dir={'WSAAPy': 'src/mypkg'},
    #package_data={'WSAAPy': ['library/*']}    
    install_requires=[
        # see notes in __init__ about the inheritance being discouraged issue
        'aiohttp==3.6.2',
        'pypac'
    ]    
)

