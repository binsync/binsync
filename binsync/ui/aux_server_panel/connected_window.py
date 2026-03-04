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
    QObject,
    QThread
)
import git
import git.exc
import functools
import pathlib
import time
l = logging.getLogger(__name__)

class ProjectCloneWorker(QObject):
    finished = Signal()
    def __init__(self, target_dir:pathlib.Path, projects: dict[str, None]):
        super().__init__()
        self.target_dir = target_dir
        self.projects = projects
    
    @Slot()
    def do_clone(self):
        l.info("Cloning projects %s into directory %s", list(self.projects.keys()), self.target_dir)
        # Collect a set of Git projects already in the directory by url
        existing_repos = set()
        for f in self.target_dir.iterdir():
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
        
        num_cloned = 0
        for project in self.projects:
            if project in existing_repos:
                continue # No need to re-clone repo, it already exists
            project_name = project.split("/")[-1]
            
            # Take out .git in url
            if project_name.endswith(".git"):
                project_name = project_name[:-4]
                
            target_path = self.target_dir.joinpath(project_name)
            if target_path.exists():
                l.info('Skipped cloning "%s" due to a file already existing at the intended path "%s"',
                        project, target_path)
                continue # Can't clone this repo into the path we want because of name conflict
            
            try:
                git.Repo.clone_from(project, str(target_path))
                num_cloned += 1
            except git.exc.GitCommandError as e: # Mainly to handle bad urls so that we can clone the other projects
                l.error("%s",e)
        l.info("Finished cloning (cloned %d new projects)", num_cloned)
        self.finished.emit()
    
        

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

class LinkedProjectItem(QWidget):
    """
    Represents a single entry in a linked project group.
    """
    ADDED_LOCALLY = 1 # Tried linking locally but not yet confirmed on server
    PRESENT_REMOTE = 2 # Project is linked on the server
    DELETED_LOCALLY = 3 # Tried deleting locally but not yet confirmed on server
    UNKNOWN = -1
    def __init__(self, project_url, state=UNKNOWN, parent=None):
        # temporary if project is not guaranteed to be known by the server yet
        super().__init__(parent)
        self.project_url = project_url
        self.state = state
        self.timestamp = -1
        self._init_widgets()
        self.update_state(self.state)
        
    def _init_widgets(self):
        layout = QHBoxLayout()            
        project_name_label = QLabel(self.project_url)
        layout.addWidget(project_name_label)
        
        self.unlink_button = QPushButton("🗑️") # Is it a good idea to use utf 8 emojis?
        layout.addWidget(self.unlink_button)
                    
        self.setLayout(layout)
    
    def update_state(self, new_state):
        # Update appearance
        if new_state == LinkedProjectItem.ADDED_LOCALLY:
            self.setStyleSheet("background-color: green")
        elif new_state == LinkedProjectItem.PRESENT_REMOTE:
            self.setStyleSheet("")
        elif new_state == LinkedProjectItem.DELETED_LOCALLY:
            self.setStyleSheet("background-color: red")
        else:
            l.error("Tried to set to unknown state %d", new_state)
            return
        self.state = new_state
        # Enable/disable button to unlink project
        if new_state == LinkedProjectItem.DELETED_LOCALLY:
            self.unlink_button.setEnabled(False)
        else:
            self.unlink_button.setEnabled(True)
        
        if new_state == LinkedProjectItem.ADDED_LOCALLY or LinkedProjectItem.DELETED_LOCALLY:
            self.timestamp = time.time() # If timestamp is expired then adhere to the state as given by server
        
        

class LinkedProjectGroup(QWidget):
    DELETE_BUTTON = "DELETE_BUTTON"
    
    def __init__(self, group_name, projects:dict[str, None], add_project_signal, unlink_project_signal, delete_group_signal, parent=None):
        super().__init__(parent)
        self.group_name = group_name
        self.projects = projects
        self.parent_add_project_signal = add_project_signal
        self.parent_unlink_project_signal = unlink_project_signal
        
        # Keeps references to the multiple project cloning workers that may be active at once
        self.clone_workers:set[ProjectCloneWorker] = set()
        self.clone_threads:set[QThread] = set()
        
        self._init_widgets(delete_group_signal)

    def _init_widgets(self, delete_group_signal):
        self.layout = QVBoxLayout()
        group_layout = QHBoxLayout()
        
        group_name_label = QLabel(self.group_name)
        group_layout.addWidget(group_name_label)
        
        download_projects_button = QPushButton("Download")
        download_projects_button.clicked.connect(self.handle_download_projects)
        group_layout.addWidget(download_projects_button)
        
        add_project_button = QPushButton("+")
        add_project_button.clicked.connect(self.handle_link_project)
        group_layout.addWidget(add_project_button)
        
        delete_group_button = QPushButton("🗑️") # Is it a good idea to use utf 8 emojis?
        delete_group_button.clicked.connect(lambda: delete_group_signal.emit(self.group_name))
        group_layout.addWidget(delete_group_button)
        
        self.layout.addLayout(group_layout)
        
        self.projects_layout = QVBoxLayout()
        for project in self.projects:
            project_widget = LinkedProjectItem(project, state=LinkedProjectItem.PRESENT_REMOTE)
            project_widget.unlink_button.clicked.connect(
                functools.partial(self.handle_unlink_project, widget=project_widget)
                    )            
            self.projects_layout.addWidget(project_widget)
        self.layout.addLayout(self.projects_layout)
        self.setLayout(self.layout)

    def handle_download_projects(self):
        """
        Downloads projects associated with this group. 
        Checks if the projects to be cloned already exist by checking for remote urls.
        Note that if the remote url uses a different protocol (e.g. ssh vs https),
        it will be treated as a different project and clone anyways.
        Will not clone a repo if there is a name conflict with a pre-existing file
        or directory.
        """
        # Save a copy of projects as they are now as we assume the download 
        # is clicked when the state looks correct to the user
        projects_to_clone = self.projects.copy()
        directory_dialog = QFileDialog(self)
        directory_dialog.setFileMode(QFileDialog.Directory)
        if directory_dialog.exec():
            target_dir = pathlib.Path(directory_dialog.selectedFiles()[0]) # Returns a list so we want to get the directory
            
            clone_worker = ProjectCloneWorker(target_dir, projects_to_clone)
            self.clone_workers.add(clone_worker)
            clone_thread = QThread()
            self.clone_threads.add(clone_thread)
            
            clone_worker.moveToThread(clone_thread)
            clone_worker.finished.connect(clone_thread.quit)
            clone_worker.finished.connect(lambda: self.clone_workers.remove(clone_worker))
            clone_worker.finished.connect(lambda: self.clone_threads.remove(clone_thread))
            clone_thread.started.connect(clone_worker.do_clone)
            
            clone_thread.start()
            
    
    def update_projects(self, projects: dict[str, None]):
        self.projects = projects
        projects_dict:dict[str, LinkedProjectItem] = {}
        while self.projects_layout.count() > 0:
            curr_project:LinkedProjectItem = self.projects_layout.takeAt(0).widget()
            projects_dict[curr_project.project_url] = curr_project
        for project_url in projects:
            if project_url in projects_dict:
                curr_project = projects_dict[project_url]
                # Check if it's possible the server just hasn't updated its state yet
                if curr_project.state == LinkedProjectItem.DELETED_LOCALLY and time.time() - curr_project.timestamp < 3:
                    pass
                else:
                    curr_project.update_state(LinkedProjectItem.PRESENT_REMOTE)
                self.projects_layout.addWidget(curr_project)

                del projects_dict[project_url]
            else:
                new_project = LinkedProjectItem(project_url, state=LinkedProjectItem.PRESENT_REMOTE)
                new_project.unlink_button.clicked.connect(
                functools.partial(self.handle_unlink_project, widget=new_project)
                    )            
                self.projects_layout.addWidget(new_project)
        
        for gone_widget in projects_dict.values():
            # Check if it's possible the server just hasn't updated its state with new project yet
            if gone_widget.state == LinkedProjectItem.ADDED_LOCALLY and time.time() - gone_widget.timestamp < 3:
                self.projects_layout.addWidget(gone_widget)
                self.projects[gone_widget.project_url] = None
            else:
                gone_widget.deleteLater()
            
    def handle_link_project(self):
        link_dialog = LinkProjectDialog(self)
        if link_dialog.exec():
            project_url = link_dialog.getInput()
            self.parent_add_project_signal.emit((project_url, self.group_name))
            temp_widget = LinkedProjectItem(project_url, state=LinkedProjectItem.ADDED_LOCALLY)
            temp_widget.unlink_button.clicked.connect(
                functools.partial(self.handle_unlink_project, widget=temp_widget)
                    )     
            self.projects_layout.addWidget(temp_widget)
            self.projects[project_url] = None
    
    def handle_unlink_project(self, widget: LinkedProjectItem):
        widget.update_state(LinkedProjectItem.DELETED_LOCALLY)
        self.parent_unlink_project_signal.emit((widget.project_url, self.group_name))
        del self.projects[widget.project_url]
        

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
        self.projects_loaded = False

        self._init_widgets()

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
        self.clear_linked_projects()
        self.projects_area_widget.setLayout(self.projects_layout)
        projects_area.setWidget(self.projects_area_widget)
        projects_area.setWidgetResizable(True)
        
        self.layout.addWidget(projects_area)
        
        add_group_button = QPushButton("Add Group")
        add_group_button.clicked.connect(self.handle_add_group)
        self.layout.addWidget(add_group_button)
        
        self.setLayout(self.layout)

    def clear_linked_projects(self):
        """
        Clears out display of linked projects (if they exist) and 
        replaces with a default message saying we are waiting for
        the server to provide projects
        """
        widgets_to_delete = self.pop_layout_items(self.projects_layout)
        if widgets_to_delete is None:
            l.error("projects layout is missing? (in clear_linked_projects)")
            return
        for widget in widgets_to_delete:
            widget.deleteLater()

        self.projects_layout.addWidget(QLabel("Waiting for server to provide linked projects...")) # This message will be replaced later
        self.projects_loaded = False
        
    @Slot()
    def handle_add_group(self):
        # Displays a dialog for group to add
        group_dialog = CreateGroupDialog()
        if group_dialog.exec():
            self.add_group.emit(group_dialog.getInput())
    
    @Slot(dict)
    def update_linked_projects(self, linked_projects: dict[str,dict[str,None]]):
        if not self.projects_loaded:
            widgets_to_delete = self.pop_layout_items(self.projects_layout)
            if widgets_to_delete is None:
                l.error("projects layout is missing?")
                return
            for widget in widgets_to_delete:
                widget.deleteLater()
            for group_name, projects in linked_projects.items():
                new_group = LinkedProjectGroup(group_name, projects, self.add_project, self.unlink_project, self.delete_group)
                self.projects_layout.addWidget(new_group)
            self.projects_loaded = True
        else:
            # Only update existing widgets to stop risk of disappearing references
            # Pop out all widgets
            old_widgets = self.pop_layout_items(self.projects_layout)
            if old_widgets is None:
                l.error("projects layout is missing?")
                return
            widgets_dict:dict[str, LinkedProjectGroup] = {}
            for widget in old_widgets:
                widgets_dict[widget.group_name] = widget
            # Send widgets back into layout as they show up in linked_projects
            for group_name, projects in linked_projects.items():
                if group_name in widgets_dict:
                    curr_widget = widgets_dict[group_name]
                    curr_widget.update_projects(projects)
                    self.projects_layout.addWidget(curr_widget)
                    del widgets_dict[group_name]
                else:
                    new_group = LinkedProjectGroup(group_name, projects, self.add_project, self.unlink_project, self.delete_group)
                    self.projects_layout.addWidget(new_group)
            # Delete widgets that were not re-added
            for gone_widget in widgets_dict.values():
                gone_widget.deleteLater()
    

    def pop_layout_items(self, layout)->list[QWidget] | list[LinkedProjectGroup] | None:
        """
        Returns a list of all top-level widgets present in the layout and deletes all non-widgets
        """
        if layout is not None:
            widgets = []
            while layout.count() > 0:
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widgets.append(widget)
                else:
                    sub_widgets = self.pop_layout_items(item.layout()) or []
                    for sub_widget in sub_widgets:
                        sub_widget.deleteLater()
            return widgets

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