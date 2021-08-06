import sys

try:
    import PySide2
    sys.modules['PySide6'] = PySide2
except ImportError:
    import PySide6
    sys.modules['PySide2'] = PySide6
from .binja_binsync import *
