import logging
from typing import List, Dict, Optional
from datetime import datetime

from libbs.ui.qt_objects import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QToolTip, 
    QMenu, QAction, QScrollArea, QFrame, QPushButton, QSizePolicy, 
    Signal, Slot, QColor, QCursor, QFont, Qt, QRect
)

from binsync.core.state import State

l = logging.getLogger(__name__)


class ChangeEntryWidget(QFrame):
    """Widget representing a single change entry in the history"""
    
    artifact_requested = Signal(object)  # Emitted when user wants to view artifact
    
    def __init__(self, change_data: Dict, parent=None):
        super().__init__(parent)
        self.change_data = change_data
        self.user_color = self._get_user_color(change_data["user"])
        self.init_ui()
        
    def init_ui(self):
        self.setFrameStyle(QFrame.StyledPanel)
        self.setLineWidth(1)
        self.setContentsMargins(5, 5, 5, 5)
        
        layout = QVBoxLayout()
        layout.setSpacing(2)
        
        # Main info line
        main_label = QLabel()
        main_label.setWordWrap(True)
        
        user = self.change_data["user"]
        operation = self.change_data["operation"]
        description = self.change_data["description"]
        timestamp = self.change_data["timestamp"]
        
        # Format timestamp
        if isinstance(timestamp, datetime):
            time_str = timestamp.strftime("%H:%M:%S")
        else:
            time_str = "unknown"
            
        user_html = f'<span style="color: {self.user_color.name()}; font-weight: bold;">{user}</span>'
        main_text = f"{user_html} {operation} {description} <span style='color: gray; font-size: 10px;'>({time_str})</span>"
        main_label.setText(main_text)
        
        layout.addWidget(main_label)
        self.setLayout(layout)
        
        # Enable hover effects
        self.setMouseTracking(True)
        
    def _get_user_color(self, username: str) -> QColor:
        """Get a consistent color for a user"""
        colors = [
            QColor("red"), QColor("blue"), QColor("green"), QColor("orange"),
            QColor("magenta"), QColor("cyan"), QColor("purple"), QColor("brown"),
            QColor("teal"), QColor("navy"), QColor("olive"), QColor("maroon")
        ]
        
        # Simple hash-based color assignment
        color_index = hash(username) % len(colors)
        return colors[color_index]
        
    def enterEvent(self, event):
        """Show tooltip on hover"""
        self.show_tooltip()
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        """Hide tooltip on leave"""
        QToolTip.hideText()
        super().leaveEvent(event)
        
    def show_tooltip(self):
        """Show detailed tooltip with artifact information"""
        artifact = self.change_data.get("artifact")
        if not artifact:
            return
            
        tooltip_text = f"<b>{artifact.__class__.__name__}</b><br>"
        tooltip_text += f"User: {self.change_data['user']}<br>"
        tooltip_text += f"Operation: {self.change_data['operation']}<br>"
        
        if hasattr(artifact, 'addr'):
            tooltip_text += f"Address: 0x{artifact.addr:x}<br>"
        if hasattr(artifact, 'name') and artifact.name:
            tooltip_text += f"Name: {artifact.name}<br>"
            
        QToolTip.showText(QCursor.pos(), tooltip_text, self, QRect(0, 0, 300, 100))
        
    def mouseDoubleClickEvent(self, event):
        """Handle double-click to view artifact"""
        artifact = self.change_data.get("artifact")
        if artifact:
            self.artifact_requested.emit(artifact)
        super().mouseDoubleClickEvent(event)
        
    def contextMenuEvent(self, event):
        """Show context menu"""
        menu = QMenu(self)
        
        view_action = QAction("View Artifact", self)
        view_action.triggered.connect(lambda: self.artifact_requested.emit(self.change_data.get("artifact")))
        menu.addAction(view_action)
        
        copy_action = QAction("Copy Description", self)
        copy_action.triggered.connect(self._copy_description)
        menu.addAction(copy_action)
        
        menu.exec_(event.globalPos())
        
    def _copy_description(self):
        """Copy the change description to clipboard"""
        from libbs.ui.qt_objects import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.change_data["description"])


class HistoryPanel(QWidget):
    """Main history panel showing live feed of changes"""
    
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.change_entries = []
        self.filtered_entries = []
        self.current_filter = ""
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Filter section
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by user, operation, or artifact...")
        self.filter_input.textChanged.connect(self.apply_filter)
        
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_filter)
        
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(clear_button)
        
        # History list
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.history_widget = QWidget()
        self.history_layout = QVBoxLayout(self.history_widget)
        self.history_layout.setAlignment(Qt.AlignTop)
        self.history_layout.setSpacing(2)
        
        self.scroll_area.setWidget(self.history_widget)
        
        # Status section
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold;")
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_history)
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.refresh_button)
        
        # Assemble layout
        layout.addLayout(filter_layout)
        layout.addWidget(self.scroll_area)
        layout.addLayout(status_layout)
        
        self.setLayout(layout)
        
    def update_history(self, state: State, changes: List[Dict]):
        """Update the history display with new changes"""
        # Add new changes
        for change in changes:
            if change not in [entry.change_data for entry in self.change_entries]:
                self.add_change_entry(change)
                
        # Update status
        if self.controller and self.controller.client:
            user = self.controller.client.user
            self.status_label.setText(f"Connected as {user} - {len(self.change_entries)} changes")
        else:
            self.status_label.setText("Disconnected")
            
    def add_change_entry(self, change_data: Dict):
        """Add a new change entry to the history"""
        entry_widget = ChangeEntryWidget(change_data)
        entry_widget.artifact_requested.connect(self.handle_artifact_request)
        
        self.change_entries.append(entry_widget)
        
        # Add to layout at the top (most recent first)
        self.history_layout.insertWidget(0, entry_widget)
        
        # Limit to last 500 entries
        if len(self.change_entries) > 500:
            old_entry = self.change_entries.pop()
            self.history_layout.removeWidget(old_entry)
            old_entry.deleteLater()
            
        self.apply_filter()
        
    def apply_filter(self):
        """Apply current filter to the change entries"""
        filter_text = self.filter_input.text().lower().strip()
        
        for entry in self.change_entries:
            change = entry.change_data
            
            # Check if entry matches filter
            matches = (
                filter_text == "" or
                filter_text in change["user"].lower() or
                filter_text in change["operation"].lower() or
                filter_text in change["description"].lower()
            )
            
            entry.setVisible(matches)
            
    def clear_filter(self):
        """Clear the current filter"""
        self.filter_input.clear()
        
    def refresh_history(self):
        """Refresh the history from the controller"""
        if not self.controller:
            return
            
        try:
            changes = self.controller.get_change_history()
            
            # Clear existing entries
            for entry in self.change_entries:
                self.history_layout.removeWidget(entry)
                entry.deleteLater()
            self.change_entries.clear()
            
            # Add all changes
            for change in reversed(changes):  # Reverse to show newest first
                self.add_change_entry(change)
                
        except Exception as e:
            l.error(f"Failed to refresh history: {e}")
            self.status_label.setText(f"Error: {e}")
            
    def handle_artifact_request(self, artifact):
        """Handle request to view an artifact"""
        if not artifact or not self.controller:
            return
            
        try:
            # Try to navigate to the artifact in the decompiler
            if hasattr(artifact, 'addr'):
                addr = artifact.addr
                if hasattr(self.controller.deci, 'goto'):
                    self.controller.deci.goto(addr)
                elif hasattr(self.controller.deci, 'navigate_to_address'):
                    self.controller.deci.navigate_to_address(addr)
                    
        except Exception as e:
            l.error(f"Failed to navigate to artifact {artifact}: {e}")
            
    def clear_history(self):
        """Clear all history entries"""
        for entry in self.change_entries:
            self.history_layout.removeWidget(entry)
            entry.deleteLater()
        self.change_entries.clear()
        self.status_label.setText("History cleared")