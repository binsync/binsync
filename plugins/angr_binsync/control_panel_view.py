from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox

from angrmanagement.ui.views.view import BaseView

from binsync.common.ui import set_ui_version
set_ui_version("PySide2")
from binsync.common.ui.control_panel import ControlPanel
from .controller import AngrBinSyncController, SyncControlStatus


class ControlPanelView(BaseView):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, workspace, default_docking_position, controller, *args, **kwargs):
        super().__init__('sync', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "BinSync: Control Panel"

        self.controller: AngrBinSyncController = controller
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

        self.width_hint = 250

    def reload(self):
        # reload the status
        #status = self.controller.status
        #if status == SyncControlStatus.CONNECTED:
        #    self._status_label.setStyleSheet("color: green")
        #elif SyncControlStatus.CONNECTED_NO_REMOTE:
        #    self._status_label.setStyleSheet("color: yellow")
        #else:
        #    self._status_label.setStyleSheet("color: red")
        #self._status_label.setText(self.controller.status_string)

        ## reload the info tables
        #if self.controller.check_client():
        #    self._update_info_tables()
        pass

    #
    # Private methods
    #

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)