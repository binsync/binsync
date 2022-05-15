from PySide2.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox


class MagicConfig(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Configure BinSync")

        self._main_layout = QVBoxLayout()

        self._init_widgets()
        self.setLayout(self._main_layout)
        self.show()

    def _init_widgets(self):
        # confirm button
        self.buttonBox = QDialogButtonBox(self)
        self.buttonBox.setStandardButtons(QDialogButtonBox.No | QDialogButtonBox.Yes)


