import idc

def get_func_name(ea):
    if hasattr(idc, 'get_func_name'):
        return idc.get_func_name(ea)
    else:
        return idc.GetFunctionName(ea)

def get_screen_ea():
    if hasattr(idc, 'get_screen_ea'):
        return idc.get_screen_ea()
    else:
        return idc.ScreenEA()
