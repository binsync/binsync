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
    QSizePolicy,
    Qt,
    QFileDialog,
)
import git
import git.exc
import functools
import pathlib
l = logging.getLogger(__name__)

class LinkProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.url_field = QLineEdit("",self)
        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        
        layout = QVBoxLayout()
        
        group_layout = QVBoxLayout()
        group_layout.addWidget(QLabel("Project URL"))
        group_layout.addWidget(self.url_field)
        layout.addLayout(group_layout)
        
        layout.addWidget(buttonBox)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        
        self.setLayout(layout)
        
    def getInput(self)->str:
        return self.url_field.text()

class LinkedProjectGroup(QWidget):
    def __init__(self, group_name, projects:dict[str, None], add_project_signal, unlink_project_signal, delete_group_signal, parent=None):
        super().__init__(parent)
        self.group_name = group_name
        self.projects = projects
        self.parent_add_project_signal = add_project_signal
        self._init_widgets(unlink_project_signal, delete_group_signal)

    def _init_widgets(self, unlink_project_signal, delete_group_signal):
        layout = QVBoxLayout()
        group_layout = QHBoxLayout()
        
        group_name_label = QLabel(self.group_name)
        group_layout.addWidget(group_name_label)
        
        download_projects_button = QPushButton("Download")
        download_projects_button.clicked.connect(self.handle_download_projects)
        group_layout.addWidget(download_projects_button)
        
        add_project_button = QPushButton("+")
        add_project_button.clicked.connect(self.handle_add_project)
        group_layout.addWidget(add_project_button)
        
        delete_group_button = QPushButton("🗑️") # Is it a good idea to use utf 8 emojis?
        delete_group_button.clicked.connect(lambda: delete_group_signal.emit(self.group_name))
        group_layout.addWidget(delete_group_button)
        
        layout.addLayout(group_layout)
        for project in self.projects:
            project_layout = QHBoxLayout()
            
            project_name_label = QLabel(project)
            project_layout.addWidget(project_name_label)
            
            unlink_project_button = QPushButton("🗑️") # Is it a good idea to use utf 8 emojis?
            unlink_project_button.clicked.connect(
                functools.partial(lambda p_name: unlink_project_signal.emit((p_name, self.group_name)), project)
                    )
            project_layout.addWidget(unlink_project_button)
            
            layout.addLayout(project_layout)
        self.setLayout(layout)

    def handle_download_projects(self):
        """
        Downloads projects associated with this group. 
        Checks if the projects to be cloned already exist by checking for remote urls.
        Note that if the remote url uses a different protocol (e.g. ssh vs https),
        it will be treated as a different project and clone anyways.
        Will not clone a repo if there is a name conflict with a pre-existing file
        or directory.
        """
        directory_dialog = QFileDialog(self)
        directory_dialog.setFileMode(QFileDialog.Directory)
        if directory_dialog.exec():
            target_dir = pathlib.Path(directory_dialog.selectedFiles()[0]) # Returns a list so we want to get the directory
            l.info("Cloning projects %s into directory %s", list(self.projects.keys()), target_dir)
            # Collect a set of Git projects already in the directory by url
            existing_repos = set()
            for f in target_dir.iterdir():
                if not f.is_dir():
                    continue
                
                try:
                    repo = git.Repo(str(f))
                    remotes = repo.remotes
                    if len(remotes) == 0:
                        continue # No remote repo so no chance of conflict
                    existing_repos.add(remotes.origin.url)
                except git.exc.InvalidGitRepositoryError:
                    pass

            for project in self.projects:
                if project in existing_repos:
                    continue # No need to re-clone repo, it already exists
                project_name = project.split("/")[-1]
                
                # Take out .git in url
                if project_name.endswith(".git"):
                    project_name = project_name[:-4]
                    
                target_path = target_dir.joinpath(project_name)
                if target_path.exists():
                    l.info('Skipped cloning "%s" due to a file already existing at the intended path "%s"',
                           project, target_path)
                    continue # Can't clone this repo into the path we want because of name conflict
                
                git.Repo.clone_from(project, str(target_path))
            l.info("Finished cloning")
                
        
    def handle_add_project(self):
        link_dialog = LinkProjectDialog()
        if link_dialog.exec():
            self.parent_add_project_signal.emit((link_dialog.getInput(), self.group_name))

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
    add_project = Signal(tuple)
    unlink_project = Signal(tuple)
    
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
        self.projects_area_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.MinimumExpanding)
        self.projects_layout = QVBoxLayout()
        self.projects_layout.setAlignment(Qt.AlignTop)
        self.projects_layout.addWidget(QLabel("Waiting for server to provide linked projects...")) # This message will be replaced later
        self.projects_area_widget.setLayout(self.projects_layout)
        projects_area.setWidget(self.projects_area_widget)
        projects_area.setWidgetResizable(True)
        
        self.layout.addWidget(projects_area)
        
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
        self.delete_layout_items(self.projects_layout)
        for group_name, projects in linked_projects.items():
            new_group = LinkedProjectGroup(group_name, projects, self.add_project, self.unlink_project, self.delete_group)
            self.projects_layout.addWidget(new_group) 

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