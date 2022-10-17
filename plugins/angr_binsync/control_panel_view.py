import logging

from angrmanagement.ui.views.view import BaseView
from binsync.common.ui.control_panel import ControlPanel
from binsync.common.ui.qt_objects import QVBoxLayout

from .controller import AngrBinSyncController


l = logging.getLogger(__name__)


class ControlPanelView(BaseView):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, instance, default_docking_position, controller, *args, **kwargs):
        super().__init__('sync', instance, default_docking_position, *args, **kwargs)

        self.base_caption = "BinSync: Control Panel"

        self.controller: AngrBinSyncController = controller
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

        self.width_hint = 300

    def reload(self):
        pass

    #
    # Private methods
    #

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)
