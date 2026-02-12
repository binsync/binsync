import logging
from libbs.ui.qt_objects import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
    Signal,
    Slot
)

l = logging.getLogger(__name__)


class LinkedProjectGroup(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        pass

class LinkedProjectsWidget(QWidget):
    list_projects = Signal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(lambda: self.list_projects.emit())
        layout.addWidget(refresh_button)

        layout.addWidget(QLabel("hello"))
        
        self.setLayout(layout)
    
    @Slot(dict)
    def update_linked_projects(self, linked_projects: dict[str,dict[str,None]]):
        l.info("updating linked projects: %s",linked_projects)

class AuxServerConnectedWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()

    def _init_widgets(self):
        disconnect_layout = QVBoxLayout()
        
        self.disconnect_button = QPushButton("Disconnect")
        disconnect_layout.addWidget(self.disconnect_button)
        
        disconnect_layout.addWidget(QLabel("Linked Projects"))

        self.linked_projects_view = LinkedProjectsWidget()
        disconnect_layout.addWidget(self.linked_projects_view)
        
        self.setLayout(disconnect_layout)