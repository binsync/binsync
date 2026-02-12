from libbs.ui.qt_objects import (
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QLineEdit,
    QDialogButtonBox,
)

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