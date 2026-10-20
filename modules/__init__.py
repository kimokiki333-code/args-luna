import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in __path__:
    __path__.insert(0, _ROOT)
