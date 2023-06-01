import sys

def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from binsync.decompilers.ida import BinsyncPlugin
    except ImportError as e:
        print(f"[!] BinSync failed to import something: {e}")
        print(f"[!] BinSync is probably not installed, please `pip install binsync` for THIS "
              f"python interpreter: {sys.executable}")

    return BinsyncPlugin(*args, **kwargs)
