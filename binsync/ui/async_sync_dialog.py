import logging
import threading
import time
from typing import Optional

from libbs.ui.qt_objects import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    Qt,
    QApplication,
    QScrollArea,
    QFrame
)

# Import QTextEdit and QTimer directly from Qt
try:
    from PySide6.QtWidgets import QTextEdit
    from PySide6.QtCore import QTimer
except ImportError:
    try:
        from PyQt5.QtWidgets import QTextEdit
        from PyQt5.QtCore import QTimer
    except ImportError:
        # Fallback - use QLabel for log display
        QTextEdit = QLabel
        QTimer = None
from libbs.artifacts import Function, Struct, Enum, GlobalVariable, Segment

l = logging.getLogger(__name__)


class AsyncSyncDialog(QDialog):
    """
    Dialog for performing async sync operations with progress tracking.
    Prevents UI freezing during large sync operations.
    """
    
    def __init__(self, controller, sync_function, sync_args, title="Syncing...", parent=None):
        super().__init__(parent)
        self.controller = controller
        self.sync_function = sync_function
        self.sync_args = sync_args
        
        self.sync_thread = None
        self.cancelled = False
        self.completed = False
        self.error = None
        
        # IDA Pro safety checks
        self._ida_safe = self._check_ida_compatibility()
        
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(500, 300)
        
        try:
            self._init_ui()
            if self._ida_safe:
                self._start_sync()
            else:
                # Run synchronously in IDA Pro
                self._run_sync_synchronously()
        except Exception as e:
            l.error(f"Failed to initialize AsyncSyncDialog: {e}")
            self.error = str(e)
            self._update_ui()
    
    def _check_ida_compatibility(self):
        """Check if we're running in IDA Pro and if async is safe"""
        try:
            import sys
            # Check for IDA modules
            ida_modules = [mod for mod in sys.modules.keys() if mod.startswith(('ida', 'idc'))]
            if ida_modules:
                l.debug("IDA Pro detected in AsyncSyncDialog")
                return False
            return True
        except Exception:
            return True  # Default to assuming it's safe
    
    def _run_sync_synchronously(self):
        """Run sync synchronously for IDA Pro compatibility"""
        try:
            self.status_label.setText("Syncing... (IDA Pro compatibility mode)")
            self.progress_bar.setRange(0, 0)  # Indeterminate
            
            # Process events to show the dialog
            try:
                from libbs.ui.qt_objects import QApplication
                app = QApplication.instance()
                if app:
                    app.processEvents()
            except Exception:
                pass
            
            # Run sync on main thread (safer for IDA)
            result = self.sync_function(**self.sync_args)
            
            self.completed = True
            self.status_label.setText("Sync completed successfully!")
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.cancel_button.setEnabled(False) 
            self.close_button.setEnabled(True)
            
            # Log result
            self._log(f"Sync completed. Changes: {result}")
            
        except Exception as e:
            self.error = str(e)
            self.status_label.setText(f"Sync failed: {e}")
            self.progress_bar.setVisible(False)
            self.cancel_button.setEnabled(False)
            self.close_button.setEnabled(True)
            self._log(f"Sync failed: {e}")
    
    def _init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        
        # Status label
        self.status_label = QLabel("Starting sync operation...")
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        layout.addWidget(self.progress_bar)
        
        # Log area
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self._cancel_sync)
        button_layout.addWidget(self.cancel_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        self.close_button.setEnabled(False)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Timer for UI updates (if available)
        if QTimer:
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self._update_ui)
            self.update_timer.start(100)  # Update every 100ms
        else:
            self.update_timer = None
    
    def _start_sync(self):
        """Start the sync operation in a background thread"""
        self.sync_thread = threading.Thread(
            target=self._run_sync_with_progress,
            daemon=True
        )
        self.sync_thread.start()
    
    def _run_sync_with_progress(self):
        """Run sync operation with progress tracking in background thread"""
        try:
            self._log("Starting sync operation...")
            
            if hasattr(self.sync_function, '__name__') and 'sync_all' in self.sync_function.__name__:
                # For sync_all, implement batched processing
                self._run_batched_sync_all()
            else:
                # For other operations, run directly
                result = self.sync_function(**self.sync_args)
                self._log(f"Sync completed. Changes: {result}")
            
            if not self.cancelled:
                self.completed = True
                self._log("Sync operation completed successfully!")
                
        except Exception as e:
            self.error = str(e)
            l.exception("Error during async sync")
            self._log(f"Error: {e}")
    
    def _run_batched_sync_all(self):
        """Run sync_all with batching and progress tracking"""
        user = self.sync_args.get('user')
        self._log(f"Getting state for user {user}...")
        
        try:
            # Get user state
            master_state, state = self.controller.get_master_and_user_state(user=user)
            
            # Count total items to sync
            total_functions = len(state.functions) if state.functions else 0
            total_structs = len(state.structs) if state.structs else 0 
            total_enums = len(state.enums) if state.enums else 0
            total_gvars = len(state.global_vars) if state.global_vars else 0
            total_segments = len(state.segments) if state.segments else 0
            
            total_items = total_functions + total_structs + total_enums + total_gvars + total_segments
            
            if total_items == 0:
                self._log("No items to sync.")
                return
            
            self._log(f"Found {total_items} items to sync ({total_functions} functions, "
                     f"{total_structs} structs, {total_enums} enums, {total_gvars} globals, "
                     f"{total_segments} segments)")
            
            # Update progress bar to show definite progress
            self.progress_bar.setRange(0, total_items)
            self.progress_bar.setValue(0)
            
            processed = 0
            batch_size = 50  # Process in batches of 50
            changes = False
            
            # Sync structs first (dependencies)
            if total_structs > 0 and not self.cancelled:
                self._log("Syncing structs...")
                changes |= self._sync_structs_batched(state, master_state, batch_size, processed)
                processed += total_structs
            
            # Sync functions 
            if total_functions > 0 and not self.cancelled:
                self._log("Syncing functions...")
                changes |= self._sync_functions_batched(state, master_state, batch_size, processed)
                processed += total_functions
            
            # Sync other artifacts
            for artifact_name, count, sync_func in [
                ("enums", total_enums, self._sync_enums_batched),
                ("global vars", total_gvars, self._sync_gvars_batched),
                ("segments", total_segments, self._sync_segments_batched)
            ]:
                if count > 0 and not self.cancelled:
                    self._log(f"Syncing {artifact_name}...")
                    changes |= sync_func(state, master_state, batch_size, processed)
                    processed += count
            
            self._log(f"Batch sync completed. Total changes: {changes}")
            
        except Exception as e:
            raise Exception(f"Error during batched sync: {e}")
    
    def _sync_functions_batched(self, state, master_state, batch_size, processed_offset):
        """Sync functions in batches with progress updates"""
        changes = False
        function_list = list(state.functions.items())
        
        for i in range(0, len(function_list), batch_size):
            if self.cancelled:
                break
                
            batch = function_list[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(function_list) + batch_size - 1) // batch_size
            
            self._log(f"Processing function batch {batch_num}/{total_batches} ({len(batch)} functions)")
            
            for addr, func in batch:
                if self.cancelled:
                    break
                    
                try:
                    change = self.controller.fill_artifact(
                        addr, artifact_type=type(func), state=state, 
                        master_state=master_state, do_type_search=False
                    )
                    changes |= change
                    
                    # Update progress
                    self.progress_bar.setValue(processed_offset + i + (batch.index((addr, func)) + 1))
                    
                except Exception as e:
                    self._log(f"Error syncing function at {hex(addr)}: {e}")
            
            # Small delay to prevent overwhelming the UI
            time.sleep(0.01)
        
        return changes
    
    def _sync_structs_batched(self, state, master_state, batch_size, processed_offset):
        """Sync structs in batches"""
        changes = False
        struct_list = list(state.structs.items())
        
        for i in range(0, len(struct_list), batch_size):
            if self.cancelled:
                break
                
            batch = struct_list[i:i + batch_size]
            self._log(f"Processing struct batch ({len(batch)} structs)")
            
            for name, struct in batch:
                if self.cancelled:
                    break
                    
                try:
                    change = self.controller.fill_artifact(
                        name, artifact_type=type(struct), state=state,
                        master_state=master_state, do_type_search=False
                    )
                    changes |= change
                    
                    self.progress_bar.setValue(processed_offset + i + (batch.index((name, struct)) + 1))
                    
                except Exception as e:
                    self._log(f"Error syncing struct {name}: {e}")
            
            time.sleep(0.01)
        
        return changes
    
    def _sync_enums_batched(self, state, master_state, batch_size, processed_offset):
        """Sync enums in batches"""
        changes = False
        enum_list = list(state.enums.items())
        
        for i in range(0, len(enum_list), batch_size):
            if self.cancelled:
                break
                
            batch = enum_list[i:i + batch_size]
            
            for name, enum in batch:
                if self.cancelled:
                    break
                    
                try:
                    change = self.controller.fill_artifact(
                        name, artifact_type=type(enum), state=state,
                        master_state=master_state, do_type_search=False
                    )
                    changes |= change
                    
                    self.progress_bar.setValue(processed_offset + i + (batch.index((name, enum)) + 1))
                    
                except Exception as e:
                    self._log(f"Error syncing enum {name}: {e}")
            
            time.sleep(0.01)
        
        return changes
    
    def _sync_gvars_batched(self, state, master_state, batch_size, processed_offset):
        """Sync global variables in batches"""
        changes = False
        gvar_list = list(state.global_vars.items())
        
        for i in range(0, len(gvar_list), batch_size):
            if self.cancelled:
                break
                
            batch = gvar_list[i:i + batch_size]
            
            for addr, gvar in batch:
                if self.cancelled:
                    break
                    
                try:
                    change = self.controller.fill_artifact(
                        addr, artifact_type=type(gvar), state=state,
                        master_state=master_state, do_type_search=False
                    )
                    changes |= change
                    
                    self.progress_bar.setValue(processed_offset + i + (batch.index((addr, gvar)) + 1))
                    
                except Exception as e:
                    self._log(f"Error syncing global var at {hex(addr)}: {e}")
            
            time.sleep(0.01)
        
        return changes
    
    def _sync_segments_batched(self, state, master_state, batch_size, processed_offset):
        """Sync segments in batches"""
        changes = False
        segment_list = list(state.segments.items())
        
        for i in range(0, len(segment_list), batch_size):
            if self.cancelled:
                break
                
            batch = segment_list[i:i + batch_size]
            
            for name, segment in batch:
                if self.cancelled:
                    break
                    
                try:
                    change = self.controller.fill_artifact(
                        name, artifact_type=type(segment), state=state,
                        master_state=master_state, do_type_search=False
                    )
                    changes |= change
                    
                    self.progress_bar.setValue(processed_offset + i + (batch.index((name, segment)) + 1))
                    
                except Exception as e:
                    self._log(f"Error syncing segment {name}: {e}")
            
            time.sleep(0.01)
        
        return changes
    
    def _cancel_sync(self):
        """Cancel the sync operation"""
        self.cancelled = True
        self._log("Cancelling sync operation...")
        self.cancel_button.setEnabled(False)
    
    def _log(self, message):
        """Thread-safe logging"""
        # Store log messages for UI thread to pick up
        if not hasattr(self, '_log_messages'):
            self._log_messages = []
        self._log_messages.append(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def _update_ui(self):
        """Update UI from main thread (called by timer)"""
        # Update log messages
        if hasattr(self, '_log_messages'):
            while self._log_messages:
                message = self._log_messages.pop(0)
                self.log_text.append(message)
                # Auto-scroll to bottom
                cursor = self.log_text.textCursor()
                cursor.movePosition(cursor.End)
                self.log_text.setTextCursor(cursor)
        
        # Update status
        if self.cancelled:
            self.status_label.setText("Sync cancelled")
            self.progress_bar.setVisible(False)
            self.close_button.setEnabled(True)
            if self.update_timer:
                self.update_timer.stop()
        elif self.completed:
            self.status_label.setText("Sync completed successfully!")
            self.progress_bar.setValue(self.progress_bar.maximum())
            self.cancel_button.setEnabled(False)
            self.close_button.setEnabled(True)
            if self.update_timer:
                self.update_timer.stop()
        elif self.error:
            self.status_label.setText(f"Sync failed: {self.error}")
            self.progress_bar.setVisible(False)
            self.cancel_button.setEnabled(False)
            self.close_button.setEnabled(True)
            if self.update_timer:
                self.update_timer.stop()
        elif self.sync_thread and self.sync_thread.is_alive():
            self.status_label.setText("Sync in progress...")
    
    def closeEvent(self, event):
        """Handle dialog close"""
        if self.sync_thread and self.sync_thread.is_alive() and not self.cancelled and not self.completed:
            # Don't allow closing while sync is running
            self._cancel_sync()
            event.ignore()
            return
        
        if self.update_timer:
            self.update_timer.stop()
        event.accept()