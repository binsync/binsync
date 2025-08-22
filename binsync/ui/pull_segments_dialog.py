import logging

from binsync.core.scheduler import SchedSpeed
from libbs.ui.qt_objects import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
    QPushButton,
    QCheckBox
)

l = logging.getLogger(__name__)


class PullSegmentsDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Pull Segments")
        self.setMinimumSize(600, 400)
        
        self._main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self._main_layout)
        
        self._populate_users()
        self._update_segments_table()

    def _init_widgets(self):
        # User selection at the top
        user_layout = QHBoxLayout()
        user_label = QLabel("Select User:")
        self.user_combo = QComboBox()
        self.user_combo.currentTextChanged.connect(self._on_user_changed)
        user_layout.addWidget(user_label)
        user_layout.addWidget(self.user_combo)
        user_layout.addStretch()
        
        # Ignore present segments checkbox
        filter_layout = QHBoxLayout()
        self.ignore_present_checkbox = QCheckBox("Ignore present segments")
        self.ignore_present_checkbox.setChecked(True)  # Checked by default
        self.ignore_present_checkbox.setToolTip(
            "When enabled, it hides all segments that the user currently has in their local decompiler. This is checked through segment names"
        )
        self.ignore_present_checkbox.stateChanged.connect(self._on_ignore_present_changed)
        filter_layout.addWidget(self.ignore_present_checkbox)
        filter_layout.addStretch()
        
        # Segments table
        self.segments_table = QTableWidget()
        self.segments_table.setColumnCount(3)
        self.segments_table.setHorizontalHeaderLabels(["Start", "End", "Name"])
        self.segments_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.segments_table.setSelectionMode(QAbstractItemView.MultiSelection)
        
        # Make the table columns resize properly
        header = self.segments_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        
        # Button layout
        button_layout = QHBoxLayout()
        self.select_all_button = QPushButton("Select All")
        self.select_all_button.clicked.connect(self._select_all)
        self.select_none_button = QPushButton("Select None")
        self.select_none_button.clicked.connect(self._select_none)
        
        button_layout.addWidget(self.select_all_button)
        button_layout.addWidget(self.select_none_button)
        button_layout.addStretch()
        
        # Confirm buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self._on_ok_clicked)
        self.button_box.rejected.connect(self._on_cancel_clicked)
        
        # Add everything to main layout
        self._main_layout.addLayout(user_layout)
        self._main_layout.addLayout(filter_layout)
        self._main_layout.addWidget(QLabel("Select segments to pull:"))
        self._main_layout.addWidget(self.segments_table)
        self._main_layout.addLayout(button_layout)
        self._main_layout.addWidget(self.button_box)

    def _populate_users(self):
        """Populate the user dropdown with users who have segments."""
        users_with_segments = []
        
        for user in self.controller.usernames(priority=1):
            try:
                cache_item = self.controller.client.check_cache_(
                    self.controller.client.get_state, user=user.name, priority=SchedSpeed.FAST
                )
                if cache_item is not None:
                    state = cache_item
                else:
                    continue

                if state and hasattr(state, 'segments') and state.segments:
                    users_with_segments.append(user)
            except Exception as e:
                l.debug("Error checking segments for user %s: %s", user, e)
                continue
        
        self.user_combo.addItems(users_with_segments)
        
        # Disable OK button if no users with segments
        if not users_with_segments:
            self.button_box.button(QDialogButtonBox.Ok).setEnabled(False)
            self.segments_table.setEnabled(False)
            # Show a message in the table
            self.segments_table.setRowCount(1)
            item = QTableWidgetItem("No users with segments found")
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.segments_table.setItem(0, 0, item)
            self.segments_table.setSpan(0, 0, 1, 3)

    def _update_segments_table(self):
        """Update the segments table based on the selected user."""
        current_user = self.user_combo.currentText()
        if not current_user:
            return
            
        try:
            cache_item = self.controller.client.check_cache_(
                self.controller.client.get_state, user=current_user, priority=SchedSpeed.FAST
            )
            if cache_item is not None:
                state = cache_item
            else:
                l.error(f"Could not retrieve state for user %s", current_user)
                return

            if not state or not hasattr(state, 'segments'):
                self.segments_table.setRowCount(0)
                return
                
            segments = state.segments
            # Filter segments if ignore present is checked
            if self.ignore_present_checkbox.isChecked():
                # Get current user's segment names
                current_segment_names = set()
                try:
                    current_segment_names = set(self.controller.deci.segments.keys())
                except Exception as e:
                    l.debug(f"Error getting current user's segments: %s", e)
                
                # Filter out segments that user already has
                filtered_segments = {
                    name: segment for name, segment in segments.items()
                    if name not in current_segment_names
                }
                segments = filtered_segments
            
            self.segments_table.setRowCount(len(segments))
            
            for row, (segment_name, segment) in enumerate(segments.items()):
                # Start address
                start_item = QTableWidgetItem(f"{segment.start_addr:#x}")
                start_item.setData(Qt.UserRole, segment_name)  # Store name as user data for identification
                self.segments_table.setItem(row, 0, start_item)
                
                # End address
                end_item = QTableWidgetItem(f"{segment.end_addr:#x}")
                self.segments_table.setItem(row, 1, end_item)
                
                # Name
                name_item = QTableWidgetItem(segment.name or "")
                self.segments_table.setItem(row, 2, name_item)
                
        except Exception as e:
            l.error("Error updating segments table for user %s: %s", current_user, e)
            self.segments_table.setRowCount(0)

    def _on_user_changed(self):
        """Handle user selection change."""
        self._update_segments_table()

    def _on_ignore_present_changed(self):
        """Handle ignore present segments checkbox change."""
        self._update_segments_table()

    def _select_all(self):
        """Select all rows in the table."""
        self.segments_table.selectAll()

    def _select_none(self):
        """Clear selection in the table."""
        self.segments_table.clearSelection()

    def _on_ok_clicked(self):
        """Handle OK button click - pull selected segments."""
        current_user = self.user_combo.currentText()
        if not current_user:
            self.close()
            return
            
        selected_rows = set()
        for item in self.segments_table.selectedItems():
            selected_rows.add(item.row())
            
        if not selected_rows:
            l.info("No segments selected for pull")
            self.close()
            return
            
        # Get the names of selected segments
        selected_names = []
        for row in selected_rows:
            start_item = self.segments_table.item(row, 0)
            if start_item:
                segment_name = start_item.data(Qt.UserRole)
                selected_names.append(segment_name)
        
        # Pull the selected segments
        try:
            for segment_name in selected_names:
                self.controller.fill_segment(segment_name, user=current_user)
            l.info("Successfully pulled %d segments from %s", len(selected_names), current_user)
        except Exception as e:
            l.error("Error pulling segments: %s", e)
            
        self.close()

    def _on_cancel_clicked(self):
        """Handle Cancel button click."""
        self.close()