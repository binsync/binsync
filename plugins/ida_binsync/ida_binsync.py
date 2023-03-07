def PLUGIN_ENTRY(*args, **kwargs):
    from binsync_bridge.idapro import BinsyncPlugin
    return BinsyncPlugin(*args, **kwargs)
