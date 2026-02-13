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
        self.groups:dict[str, LinkedProjectGroup] = {}

    def _init_widgets(self):
        self.layout = QVBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(lambda: self.list_projects.emit())
        self.layout.addWidget(refresh_button)

        self.projects_layout = QVBoxLayout()
        self.projects_layout.addWidget(QLabel("Waiting for server to provide linked projects..."))
        self.layout.addLayout(self.projects_layout) # It's going to be replaced later
        
        self.setLayout(self.layout)
    
    @Slot(dict)
    def update_linked_projects(self, linked_projects: dict[str,dict[str,None]]):
        l.info("updating linked projects: %s",linked_projects)
        self.delete_layout_items(self.projects_layout)
        self.projects_layout.deleteLater()
        self.layout.removeItem(self.projects_layout)
        
        new_layout = QVBoxLayout()
        new_layout.addWidget(QLabel(str(linked_projects))) 
        self.projects_layout = new_layout
        self.layout.addLayout(self.projects_layout)
        self.updateGeometry()


    def delete_layout_items(self, layout):
        if layout:
            while layout.count() > 0:
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.setParent(None)
                    widget.deleteLater()
                else:
                    self.delete_layout_items(item.layout())


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