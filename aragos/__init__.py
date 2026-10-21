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

import argus
sys.modules.setdefault("argus", argus)

__version__ = "3.0.0"
__app_name__ = "ARAGOS"
