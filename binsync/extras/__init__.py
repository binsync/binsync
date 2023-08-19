import logging
logging.getLogger("angr").setLevel(logging.ERROR)

_l = logging.getLogger(__name__)

# place all required head imports for extras
EXTRAS_AVAILABLE = True
try:
    # AI Extras
    import dailalib
except ImportError:
    _l.info("Extras not installed, some features will not be available.")
    EXTRAS_AVAILABLE = False
