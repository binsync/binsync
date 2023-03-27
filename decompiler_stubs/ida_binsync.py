def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from binsync.decompilers.ida import BinsyncPlugin
    except ImportError:
        print("[!] BinSync is not installed, please `pip install binsync` for THIS python interpreter")
        return None

    return BinsyncPlugin(*args, **kwargs)
