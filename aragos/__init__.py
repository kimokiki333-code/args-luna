import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in __path__:
    __path__.insert(0, _ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import argus
sys.modules.setdefault("argus", argus)

__version__ = "3.0.0"
__app_name__ = "ARAGOS"
