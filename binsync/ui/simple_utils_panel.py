import logging
from typing import Optional

from libbs.ui.qt_objects import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QCheckBox, QGroupBox,
    QLineEdit, Signal, Slot
)

l = logging.getLogger(__name__)


class SimpleUtilsPanel(QWidget):
    """Simplified utilities panel for the new BinSync architecture"""
    
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Connection Status Group
        self.create_status_group(layout)
        
        # Sync Settings Group
        self.create_sync_settings_group(layout)
        
        # Quick Actions Group
        self.create_quick_actions_group(layout)
        
        # Repository Info Group
        self.create_repo_info_group(layout)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def create_status_group(self, parent_layout):
        """Create the connection status group"""
        group = QGroupBox("Connection Status")
        layout = QVBoxLayout()
        
        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        
        self.user_label = QLabel("User: Not connected")
        self.repo_label = QLabel("Repository: None")
        
        layout.addWidget(self.status_label)
        layout.addWidget(self.user_label)
        layout.addWidget(self.repo_label)
        
        group.setLayout(layout)
        parent_layout.addWidget(group)
        
    def create_sync_settings_group(self, parent_layout):
        """Create the sync settings group"""
        group = QGroupBox("Sync Settings")
        layout = QGridLayout()
        
        # Auto-commit setting
        self.auto_commit_cb = QCheckBox("Auto Commit")
        self.auto_commit_cb.setChecked(True)
        self.auto_commit_cb.stateChanged.connect(self.on_auto_commit_changed)
        
        # Auto-push setting
        self.auto_push_cb = QCheckBox("Auto Push")
        self.auto_push_cb.setChecked(True)
        self.auto_push_cb.stateChanged.connect(self.on_auto_push_changed)
        
        # Auto-pull setting
        self.auto_pull_cb = QCheckBox("Auto Pull")
        self.auto_pull_cb.setChecked(True)
        self.auto_pull_cb.stateChanged.connect(self.on_auto_pull_changed)
        
        # Sync interval
        layout.addWidget(QLabel("Sync Interval (seconds):"), 3, 0)
        self.sync_interval_input = QLineEdit()
        self.sync_interval_input.setText("10")
        self.sync_interval_input.textChanged.connect(self.on_sync_interval_changed)
        
        layout.addWidget(self.auto_commit_cb, 0, 0)
        layout.addWidget(self.auto_push_cb, 1, 0)
        layout.addWidget(self.auto_pull_cb, 2, 0)
        layout.addWidget(self.sync_interval_input, 3, 1)
        
        group.setLayout(layout)
        parent_layout.addWidget(group)
        
    def create_quick_actions_group(self, parent_layout):
        """Create the quick actions group"""
        group = QGroupBox("Quick Actions")
        layout = QVBoxLayout()
        
        # Manual sync buttons
        sync_layout = QHBoxLayout()
        
        self.pull_button = QPushButton("Pull Now")
        self.pull_button.clicked.connect(self.manual_pull)
        
        self.push_button = QPushButton("Push Now")
        self.push_button.clicked.connect(self.manual_push)
        
        sync_layout.addWidget(self.pull_button)
        sync_layout.addWidget(self.push_button)
        
        # Force push current function
        self.force_push_func_button = QPushButton("Force Push Current Function")
        self.force_push_func_button.clicked.connect(self.force_push_current_function)
        
        # Clear history
        self.clear_history_button = QPushButton("Clear History")
        self.clear_history_button.clicked.connect(self.clear_history)
        
        layout.addLayout(sync_layout)
        layout.addWidget(self.force_push_func_button)
        layout.addWidget(self.clear_history_button)
        
        group.setLayout(layout)
        parent_layout.addWidget(group)
        
    def create_repo_info_group(self, parent_layout):
        """Create the repository information group"""
        group = QGroupBox("Repository Information")
        layout = QVBoxLayout()
        
        self.repo_info_text = QLabel("No repository information available")
        self.repo_info_text.setMaximumHeight(100)
        self.repo_info_text.setWordWrap(True)
        self.repo_info_text.setStyleSheet("border: 1px solid gray; padding: 5px;")
        
        refresh_button = QPushButton("Refresh Info")
        refresh_button.clicked.connect(self.refresh_repo_info)
        
        layout.addWidget(self.repo_info_text)
        layout.addWidget(refresh_button)
        
        group.setLayout(layout)
        parent_layout.addWidget(group)
        
    def update_status(self):
        """Update the status display"""
        if not self.controller or not self.controller.check_client():
            self.status_label.setText("Disconnected")
            self.user_label.setText("User: Not connected")
            self.repo_label.setText("Repository: None")
            
            # Disable controls
            self.auto_commit_cb.setEnabled(False)
            self.auto_push_cb.setEnabled(False)
            self.auto_pull_cb.setEnabled(False)
            self.pull_button.setEnabled(False)
            self.push_button.setEnabled(False)
            self.force_push_func_button.setEnabled(False)
            return
            
        # Enable controls
        self.auto_commit_cb.setEnabled(True)
        self.auto_push_cb.setEnabled(True)
        self.auto_pull_cb.setEnabled(True)
        self.pull_button.setEnabled(True)
        self.push_button.setEnabled(True)
        self.force_push_func_button.setEnabled(True)
        
        # Update status
        status = self.controller.status()
        from binsync.controller import SyncControlStatus
        
        if status == SyncControlStatus.CONNECTED:
            self.status_label.setText("Connected")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 12px; color: green;")
        elif status == SyncControlStatus.CONNECTED_NO_REMOTE:
            self.status_label.setText("Connected (No Remote)")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 12px; color: orange;")
        elif status == SyncControlStatus.LOADING:
            self.status_label.setText("Loading...")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 12px; color: blue;")
        else:
            self.status_label.setText("Disconnected")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 12px; color: red;")
            
        # Update user and repo info
        client = self.controller.client
        self.user_label.setText(f"User: {client.user}")
        self.repo_label.setText(f"Repository: {client.repo_path}")
        
        # Update checkbox states
        self.auto_commit_cb.setChecked(self.controller.auto_commit_enabled)
        self.auto_push_cb.setChecked(self.controller.auto_push_enabled)
        self.auto_pull_cb.setChecked(self.controller.auto_pull_enabled)
        self.sync_interval_input.setText(str(self.controller.reload_time))
        
    @Slot()
    def on_auto_commit_changed(self):
        """Handle auto-commit setting change"""
        if self.controller:
            self.controller.auto_commit_enabled = self.auto_commit_cb.isChecked()
            
    @Slot()
    def on_auto_push_changed(self):
        """Handle auto-push setting change"""
        if self.controller:
            self.controller.auto_push_enabled = self.auto_push_cb.isChecked()
            
    @Slot()
    def on_auto_pull_changed(self):
        """Handle auto-pull setting change"""
        if self.controller:
            self.controller.auto_pull_enabled = self.auto_pull_cb.isChecked()
            
    @Slot()
    def on_sync_interval_changed(self):
        """Handle sync interval change"""
        if self.controller:
            try:
                value = int(self.sync_interval_input.text())
                if 5 <= value <= 300:  # Reasonable bounds
                    self.controller.reload_time = value
            except ValueError:
                pass  # Ignore invalid input
            
    @Slot()
    def manual_pull(self):
        """Manually trigger a pull"""
        if self.controller and self.controller.check_client():
            try:
                success = self.controller.client.pull_and_update()
                if success:
                    self.status_label.setText("Pull completed successfully")
                else:
                    self.status_label.setText("Pull failed")
            except Exception as e:
                l.error(f"Manual pull failed: {e}")
                self.status_label.setText(f"Pull error: {e}")
                
    @Slot()
    def manual_push(self):
        """Manually trigger a push"""
        if self.controller and self.controller.check_client():
            try:
                success = self.controller.client.push_changes()
                if success:
                    self.status_label.setText("Push completed successfully")
                else:
                    self.status_label.setText("Push failed")
            except Exception as e:
                l.error(f"Manual push failed: {e}")
                self.status_label.setText(f"Push error: {e}")
                
    @Slot()
    def force_push_current_function(self):
        """Force push the currently active function"""
        if not self.controller or not self.controller.check_client():
            return
            
        try:
            if self.controller.last_active_func:
                func = self.controller.last_active_func
                success = self.controller.force_push_artifact(func)
                if success:
                    self.status_label.setText(f"Force pushed function {func.name or hex(func.addr)}")
                else:
                    self.status_label.setText("Force push failed")
            else:
                self.status_label.setText("No active function to push")
        except Exception as e:
            l.error(f"Force push failed: {e}")
            self.status_label.setText(f"Force push error: {e}")
            
    @Slot()
    def clear_history(self):
        """Clear the change history"""
        if self.controller:
            # Clear controller's change history
            self.controller._change_history.clear()
            self.status_label.setText("History cleared")
            
            # Also clear the UI history if we can access it
            try:
                # This would need to be connected to the history panel
                # For now, just update the status
                pass
            except Exception as e:
                l.debug(f"Could not clear UI history: {e}")
                
    @Slot()
    def refresh_repo_info(self):
        """Refresh repository information"""
        if not self.controller or not self.controller.check_client():
            self.repo_info_text.setPlainText("No repository information available")
            return
            
        try:
            client = self.controller.client
            info_lines = [
                f"User: {client.user}",
                f"Repository Path: {client.repo_path}",
                f"Remote URL: {client.remote_url or 'None'}",
                f"Binary Hash: {client.binary_hash}",
            ]
            
            # Add user list
            try:
                users = client.get_users()
                user_names = [user.name for user in users]
                info_lines.append(f"Users: {', '.join(user_names)}")
            except Exception as e:
                info_lines.append(f"Users: Error getting users ({e})")
                
            # Add last sync times
            if client._last_pull_time:
                info_lines.append(f"Last Pull: {client._last_pull_time}")
            if client._last_push_time:
                info_lines.append(f"Last Push: {client._last_push_time}")
                
            self.repo_info_text.setText("\n".join(info_lines))
            
        except Exception as e:
            l.error(f"Failed to refresh repo info: {e}")
            self.repo_info_text.setText(f"Error getting repository information: {e}")