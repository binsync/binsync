import logging
from declib.ui.qt_objects import (
    QFormLayout,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QDialogButtonBox,
)

l = logging.getLogger(__name__)


class AuxServerDisconnectedWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        self.first = QLineEdit("[::1]", self)
        self.second = QLineEdit("7962", self)
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)

        form = QFormLayout()
        form.addRow("Host", self.first)
        form.addRow("Port", self.second)

        self.connect_layout = QVBoxLayout()
        self.connect_layout.addLayout(form)
        self.connect_layout.addStretch(1)
        self.connect_layout.addWidget(self.buttonBox)
        self.setLayout(self.connect_layout)

    def get_inputs(self) -> tuple[str, str]:
        return (self.first.text(), self.second.text())