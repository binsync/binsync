def PLUGIN_ENTRY(*args, **kwargs):
    from ida_binsync.plugin import BinsyncPlugin

    return BinsyncPlugin(*args, **kwargs)
