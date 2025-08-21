import logging

from libbs.ui.qt_objects import (
    QWidget, QVBoxLayout, QTabWidget, QLabel, QStatusBar, Signal, Slot
)

from binsync.ui.simple_history_panel import HistoryPanel
from binsync.ui.simple_utils_panel import SimpleUtilsPanel

l = logging.getLogger(__name__)


class SimpleControlPanel(QWidget):
    """Simplified control panel for the new single-branch BinSync architecture"""
    
    update_ready = Signal(str)
    
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.init_ui()
        
        # Register controller callbacks
        self.update_ready.connect(self.reload)
        self.controller.ui_callback = self.update_callback
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # History tab (main tab)
        self.history_panel = HistoryPanel(self.controller)
        self.tab_widget.addTab(self.history_panel, "Live History")
        
        # Utilities tab
        self.utils_panel = SimpleUtilsPanel(self.controller)
        self.tab_widget.addTab(self.utils_panel, "Utilities")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Disconnected")
        self.status_bar.addPermanentWidget(self.status_label)
        
        # Assemble layout
        layout.addWidget(self.tab_widget)
        layout.addWidget(self.status_bar)
        
        self.setLayout(layout)
        
        # Set initial size
        self.resize(800, 600)
        
    def update_callback(self, state, changes):
        """Callback from controller when state/changes are updated"""
        try:
            # Update history panel
            self.history_panel.update_history(state, changes)
            
            # Update status
            status = self.controller.status_string() if self.controller else "Disconnected"
            self.update_ready.emit(status)
            
        except Exception as e:
            l.error(f"Error in update callback: {e}")
            
    @Slot(str)
    def reload(self, status):
        """Reload UI with new status"""
        self.status_label.setText(status)
        
        # Update utils panel status
        self.utils_panel.update_status()
        
    def closeEvent(self, event):
        """Handle close event"""
        if self.controller:
            self.controller.ui_callback = None
            self.controller.shutdown()
        event.accept()