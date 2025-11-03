from libbs.ui.qt_objects import (
    # QtWidgets
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QLabel
)
class HistoryDisplayWidget(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent)
        self._init_widgets()
        
    def _init_widgets(self):
        self.setWindowTitle("History")
        
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        bottom_layout = QVBoxLayout()
        
        top_layout.addWidget(QLabel("top"))
        bottom_layout.addWidget(QLabel("bottom"))
        
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
        
        self.setLayout(main_layout)
        self.resize(1000, 800)
