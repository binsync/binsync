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
)
from libbs.artifacts import (
    Context
)
from binsync.ui.magic_sync_dialog import MagicSyncDialog
from binsync.ui.force_push import ForcePushUI
from binsync.ui.utils import no_concurrent_call
from binsync.controller import BSController
from binsync.extras import EXTRAS_AVAILABLE

# There are type warnings with the display_clients signal when ClientWorker is placed at the bottom
class ClientWorker(QObject):
    finished = Signal()
    context_change = Signal(dict)
    def __init__(self,host:str,port:int,controller):
        super().__init__()
        from binsync.extras.aux_server.aux_client import ServerClient # Import is put in here because it should only be done if extras are available

        self.server_client = ServerClient(host,port,controller,self.client_context_callback)
        
    def run(self):
        self.server_client.run()
        self.finished.emit()
    
    def client_context_callback(self, contexts: dict[str,dict[str,int]]):
        self.context_change.emit(contexts)
    
    def stop(self):
        self.server_client.stop()

class AuxServerWidget(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()
        
    def _init_widgets(self):
        self.setWindowTitle("Auxiliary Server")