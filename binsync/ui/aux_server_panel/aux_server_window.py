'''
Don't import unless extras are enabled as we import from aux_server at the top level
'''
import logging

from binsync.ui.aux_server_panel.connected_window import AuxServerConnectedWidget
from binsync.ui.aux_server_panel.disconnected_window import AuxServerDisconnectedWidget
from libbs.ui.qt_objects import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QObject,
    Signal,
    QDialog,
    QLineEdit,
    QDialogButtonBox,
    Slot,
    QStackedLayout,
    QTimer
)
from functools import wraps
from binsync.extras.aux_server.aux_client import ServerClient

l = logging.getLogger(__name__)
    
def _client_required(func):
    @wraps(func) # appears to be necessary to avoid RecursionError when timer in ClientWorker calls _client_context_callback
    def check_for_connected(self, *args, **kwargs):
        if self.server_client is not None:
            return func(self, *args, **kwargs)
        else:
            l.error("Tried to call a method that requires a server client to exist") 
    return check_for_connected

# There are type warnings with the display_clients signal when ClientWorker is placed at the bottom
class ClientWorker(QObject):
    finished = Signal()
    context_change = Signal(dict)
    client_connected = Signal(bool)
    projects_list = Signal(dict)
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.server_client = None
        self.timer = None
        
    @Slot(tuple) # Using @Slot is MANDATORY as it blocks in main thread otherwise
    def connect_client(self, host_and_port):
        if self.server_client is not None:
            return # We've already connected and should wait for a disconnect signal
        host, port = host_and_port
        self.server_client = ServerClient(host, port, self.controller)
        success = self.server_client.connect()
        if not success:
            self.server_client.stop()
            self.server_client = None
            return # Client failed to connect so no need to do remaining setup
        self.client_connected.emit(True)
        self.timer = QTimer()
        self.timer.timeout.connect(self._client_context_callback)
        self.timer.start(1000)
    
    @Slot()    
    @_client_required
    def _client_context_callback(self):
        user_contexts = self.server_client.poll_users_data() # type: ignore (is ok because of _client_required decorator)
        if user_contexts is not None: # Connection with server might have dropped
            self.context_change.emit(user_contexts)
        else:
            self.disconnect_client()
    
    @Slot()
    @_client_required
    def get_linked_projects(self):
        linked_projects = self.server_client.list_projects() # type: ignore
        self.projects_list.emit(linked_projects)
    
    @Slot(tuple)
    @_client_required
    def link_project(self, project_info):
        url, group = project_info
        result = self.server_client.link_project(url, group) # type: ignore
        if result[0] == False:
            l.error(result[1])
        self.get_linked_projects()
    
    @Slot(tuple)
    @_client_required
    def unlink_project(self, project_info):
        url, group = project_info
        result = self.server_client.unlink_project(url, group) # type: ignore
        if result[0] == False:
            l.error(result[1])
        self.get_linked_projects()
    
    @Slot(str)
    @_client_required
    def add_group(self, group_name):
        result = self.server_client.create_group(group_name) # type: ignore
        if result[0] == False:
            l.error(result[1])
        self.get_linked_projects()
        
    @Slot(str)
    @_client_required
    def delete_group(self, group_name):
        result = self.server_client.delete_group(group_name) # type: ignore
        if result[0] == False:
            l.error(result[1])
        self.get_linked_projects()
    
    @Slot() 
    @_client_required
    def disconnect_client(self):
        if self.timer: # Might have run into an error making the client connect
            self.timer.stop()
            self.timer = None
        self.server_client.stop() # type: ignore (is ok because of _client_required decorator)
        self.client_connected.emit(False)
        self.server_client = None
    
    # Are there issues with stop being called multiple times? (On disconnect button click & on connection being dropped)
    @Slot() 
    def stop(self): 
        if self.server_client is not None:
            self.disconnect_client()
        self.finished.emit()
            
class AuxServerWidget(QDialog):
    '''
    This should be the widget that you create when producing the server interface
    '''
    connect_signal = Signal(tuple)
    disconnect_signal = Signal()
    
    DISCONNECTED_INDEX = 0
    CONNECTED_INDEX = 1
    
    def __init__(self, connected:bool, parent=None):
        super().__init__(parent)
        self._init_widgets(connected)
        self.setWindowTitle("Server")
    
    def connect_worker(self, client_worker:ClientWorker):
        """
        Links up signals & slots of worker with this popup window
        """
        self.connect_signal.connect(client_worker.connect_client)
        self.disconnect_signal.connect(client_worker.disconnect_client)
        self.connected_widget.linked_projects_view.list_projects.connect(client_worker.get_linked_projects)
        self.connected_widget.linked_projects_view.add_project.connect(client_worker.link_project)
        self.connected_widget.linked_projects_view.unlink_project.connect(client_worker.unlink_project)
        self.connected_widget.linked_projects_view.add_group.connect(client_worker.add_group)
        self.connected_widget.linked_projects_view.delete_group.connect(client_worker.delete_group)
        
        
        client_worker.client_connected.connect(self.update_layout)
        client_worker.projects_list.connect(self.connected_widget.linked_projects_view.update_linked_projects)
        
    def startup_emits(self):
        """
        Performs initial emits to improve initial page appearance for users
        """
        self.connected_widget.linked_projects_view.list_projects.emit()
        
    def _init_widgets(self, connected:bool):
        self.disconnected_widget = AuxServerDisconnectedWidget(self)
        self.disconnected_widget.buttonBox.accepted.connect(self.try_connect)
        
        self.connected_widget = AuxServerConnectedWidget(self)
        self.connected_widget.disconnect_button.clicked.connect(lambda: self.disconnect_signal.emit())
        
        self.stacked_layout = QStackedLayout()
        self.stacked_layout.addWidget(self.disconnected_widget)
        self.stacked_layout.addWidget(self.connected_widget)
            
        self.stacked_layout.setCurrentIndex(self.DISCONNECTED_INDEX if not connected else self.CONNECTED_INDEX)
        self.resize(1000, 800)
        self.setLayout(self.stacked_layout)

    @Slot()
    def try_connect(self):
        host_str, port_str = self.disconnected_widget.get_inputs()
        try:
            port = int(port_str)
        except ValueError:
            l.error("Port provided could not be parsed as an int")
        else:
            self.connect_signal.emit((host_str,port))            

    @Slot(bool)
    def update_layout(self, connected):
        if not connected:
            self.connected_widget.linked_projects_view.clear_linked_projects() # Get rid of linked projects. We may connect somewhere else
            self.stacked_layout.setCurrentIndex(self.DISCONNECTED_INDEX)
        else:
            self.connected_widget.linked_projects_view.list_projects.emit() # Load in linked projects
            self.stacked_layout.setCurrentIndex(self.CONNECTED_INDEX)
    
    