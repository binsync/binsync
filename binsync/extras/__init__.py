import logging
logging.getLogger("angr").setLevel(logging.ERROR)

# place all required head imports for extras
EXTRAS_AVAILABLE = True
try:
    import daila
    import angr
except ImportError:
    EXTRAS_AVAILABLE = False

if EXTRAS_AVAILABLE:
    from binsync.extras.ai.openai_bs_user import add_openai_user_to_project
