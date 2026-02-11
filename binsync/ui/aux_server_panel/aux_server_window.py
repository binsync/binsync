import logging
import time
import requests
import urllib.parse

from libbs.ui.qt_objects import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    Qt,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QIntValidator,
    QThread,
    QObject,
    Signal,
    QDialog,
    QLineEdit,
    QDialogButtonBox,
    Slot,
    QStackedLayout
)
from libbs.artifacts import (
    Context
)
from binsync.ui.magic_sync_dialog import MagicSyncDialog
from binsync.ui.force_push import ForcePushUI
from binsync.ui.utils import no_concurrent_call
from binsync.controller import BSController
from binsync.extras import EXTRAS_AVAILABLE

l = logging.getLogger(__name__)
    
class AuxServerDisconnectedWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        self.first = QLineEdit("[::1]",self)
        self.second = QLineEdit("7962",self)
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        
        self.connect_layout = QVBoxLayout()
        inputs_layout = QHBoxLayout()
        
        host_layout = QVBoxLayout()
        host_layout.addWidget(QLabel("Host"))
        host_layout.addWidget(self.first)
        inputs_layout.addLayout(host_layout)
        
        port_layout = QVBoxLayout()
        port_layout.addWidget(QLabel("Port"))
        port_layout.addWidget(self.second)
        inputs_layout.addLayout(port_layout)

        self.connect_layout.addLayout(inputs_layout)
        
        self.connect_layout.addWidget(self.buttonBox)
        self.setLayout(self.connect_layout)
    
    def get_inputs(self)->tuple[str,str]:
        return (self.first.text(), self.second.text())

class AuxServerConnectedWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        self.disconnect_layout = QVBoxLayout()
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_layout.addWidget(self.disconnect_button)
        self.setLayout(self.disconnect_layout)
            
class AuxServerWidget(QDialog):
    '''
    This should be the widget that you create when producing the server interface
    '''
    connect_signal = Signal(tuple)
    disconnect_signal = Signal()
    
    DISCONNECTED_INDEX = 0
    CONNECTED_INDEX = 1
    
    def __init__(self, connected:bool, parent=None):
        super().__init__(parent)
        self._init_widgets(connected)
        self.setWindowTitle("Server")
        
    def _init_widgets(self, connected:bool):
        self.disconnected_widget = AuxServerDisconnectedWidget(self)
        self.disconnected_widget.buttonBox.accepted.connect(self.try_connect)
        
        self.connected_widget = AuxServerConnectedWidget(self)
        self.connected_widget.disconnect_button.clicked.connect(lambda: self.disconnect_signal.emit())
        
        self.stacked_layout = QStackedLayout()
        self.stacked_layout.addWidget(self.disconnected_widget)
        self.stacked_layout.addWidget(self.connected_widget)
            
        self.stacked_layout.setCurrentIndex(self.DISCONNECTED_INDEX)
        self.resize(1000, 800)

    @Slot()
    def try_connect(self):
        host_str, port_str = self.disconnected_widget.get_inputs()
        try:
            port = int(port_str)
        except ValueError:
            l.error("Port provided could not be parsed as an int")
        else:
            self.connect_signal.emit((host_str,port))            

    @Slot(bool)
    def update_layout(self, connected):
        if not connected:
            self.stacked_layout.setCurrentIndex(self.DISCONNECTED_INDEX)
        else:
            self.stacked_layout.setCurrentIndex(self.CONNECTED_INDEX)
    
    