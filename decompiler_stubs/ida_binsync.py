def PLUGIN_ENTRY(*args, **kwargs):
    from binsync.decompilers.ida import BinsyncPlugin
    return BinsyncPlugin(*args, **kwargs)
