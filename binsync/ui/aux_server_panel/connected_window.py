import logging
from libbs.ui.qt_objects import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
    Signal,
    Slot,
    QScrollArea,
    QDialog,
    QLineEdit,
    QDialogButtonBox,
)

l = logging.getLogger(__name__)


class LinkedProjectGroup(QWidget):
    def __init__(self, group_name, projects:dict[str,None], parent=None):
        super().__init__(parent)
        self._init_widgets(group_name, projects)

    def _init_widgets(self, group_name, projects):
        layout = QVBoxLayout()
        group_layout = QHBoxLayout()
        group_layout.addWidget(QLabel(group_name))
        add_project_button = QPushButton("+")
        group_layout.addWidget(add_project_button)
        layout.addLayout(group_layout)
        for project in projects:
            layout.addWidget(QLabel(project))
        self.setLayout(layout)

class CreateGroupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.group_field = QLineEdit("",self)
        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        
        layout = QVBoxLayout()
        
        group_layout = QVBoxLayout()
        group_layout.addWidget(QLabel("Group Name"))
        group_layout.addWidget(self.group_field)
        layout.addLayout(group_layout)
        
        layout.addWidget(buttonBox)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        
        self.setLayout(layout)
        
    def getInput(self)->str:
        return self.group_field.text()

class LinkedProjectsWidget(QWidget):
    list_projects = Signal()
    add_group = Signal(str)
    delete_group = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_widgets()
        self.groups:dict[str, LinkedProjectGroup] = {}

    def _init_widgets(self):
        self.layout = QVBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(lambda: self.list_projects.emit())
        self.layout.addWidget(refresh_button)

        projects_area = QScrollArea()
        self.projects_area_widget = QWidget()
        self.projects_layout = QVBoxLayout()
        self.projects_layout.addWidget(QLabel("Waiting for server to provide linked projects..."))
        self.projects_area_widget.setLayout(self.projects_layout)
        projects_area.setWidget(self.projects_area_widget)
        
        self.layout.addWidget(projects_area) # It's going to be replaced later
        
        add_group_button = QPushButton("Add Group")
        add_group_button.clicked.connect(self.handle_add_group)
        self.layout.addWidget(add_group_button)
        
        self.setLayout(self.layout)
        
    @Slot()
    def handle_add_group(self):
        # Displays a dialog for group to add
        group_dialog = CreateGroupDialog()
        if group_dialog.exec():
            self.add_group.emit(group_dialog.getInput())
    
    @Slot(dict)
    def update_linked_projects(self, linked_projects: dict[str,dict[str,None]]):
        # self.delete_layout_items(self.projects_layout)
        for group_name, projects in linked_projects.items():
            self.projects_layout.addWidget(LinkedProjectGroup(group_name, projects)) 
        self.projects_area_widget.adjustSize()

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