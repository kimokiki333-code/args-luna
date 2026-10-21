import os
import sys

_CANDIDATES = [
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    os.getcwd(),
    "/var/task",
]
for _p in _CANDIDATES:
    if _p and os.path.isdir(_p):
        if _p not in __path__:
            __path__.insert(0, _p)
        if _p not in sys.path:
            sys.path.insert(0, _p)

_SYS_CA = "/etc/ssl/certs/ca-certificates.crt"
if os.path.isfile(_SYS_CA):
    os.environ.setdefault("REQUESTS_CA_BUNDLE", _SYS_CA)
    os.environ.setdefault("SSL_CERT_FILE", _SYS_CA)
    os.environ.setdefault("CURL_CA_BUNDLE", _SYS_CA)

__version__ = "3.0.0"
__app_name__ = "ARAGOS"
