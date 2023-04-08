from ..common.controller import BinSyncController

class BaseBSPlugin:
    TOP_MENU_NAME = ""

    def __init__(self, controller: BinSyncController):
        self.controller = controller

    def register_bs_menu_item(self, item_str, callback_function):
        pass