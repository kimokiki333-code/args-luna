import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in __path__:
    __path__.insert(0, _ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_SYS_CA = "/etc/ssl/certs/ca-certificates.crt"
if os.path.isfile(_SYS_CA):
    os.environ.setdefault("REQUESTS_CA_BUNDLE", _SYS_CA)
    os.environ.setdefault("SSL_CERT_FILE", _SYS_CA)
    os.environ.setdefault("CURL_CA_BUNDLE", _SYS_CA)

__version__ = "3.0.0"
__app_name__ = "ARAGOS"
