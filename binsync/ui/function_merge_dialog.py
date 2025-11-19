import logging

from libbs.ui.qt_objects import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QVBoxLayout,
    QLabel,
    QComboBox,
    Qt,
)


_l = logging.getLogger(__name__)


class FunctionNameMergeDialog(QDialog):
    """
    Dialog for resolving a function name conflict between the current and
    incoming versions of a function.

    It presents the two candidate signatures and lets the user choose which
    name should be used in the final merged state via a dropdown.
    """

    def __init__(self, current_signature, incoming_signature, parent=None):
        super().__init__(parent)
        self._current_signature = current_signature
        self._incoming_signature = incoming_signature

        self.selected_source = "current"

        self.setWindowTitle("Resolve Function Name Conflict")
        self._main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self._main_layout)

    def _init_widgets(self):
        layout = QVBoxLayout()

        info_label = QLabel(self)
        info_label.setWordWrap(True)
        info_label.setText(
            """<html>
            <p>
            A conflict was detected between the current and incoming function names.<br>
            Select which name you would like to keep for the final state.
            </p>
            </html>
            """
        )
        layout.addWidget(info_label)

        grid = QGridLayout()
        current_label = QLabel("Current:", self)
        incoming_label = QLabel("Incoming:", self)

        current_value = QLabel(self._current_signature or "&lt;no name&gt;", self)
        incoming_value = QLabel(self._incoming_signature or "&lt;no name&gt;", self)

        grid.addWidget(current_label, 0, 0)
        grid.addWidget(current_value, 0, 1)
        grid.addWidget(incoming_label, 1, 0)
        grid.addWidget(incoming_value, 1, 1)

        layout.addLayout(grid)

        choice_label = QLabel("Final name:", self)
        self._choice_combo = QComboBox(self)
        # Highlight the dropdown to indicate there is a conflict to resolve
        self._choice_combo.setStyleSheet(
            "QComboBox { background-color: rgb(255, 255, 200); }"
        )

        current_text = self._current_signature or "<no name>"
        incoming_text = self._incoming_signature or "<no name>"

        self._choice_combo.addItem(current_text, userData="current")
        if incoming_text != current_text:
            self._choice_combo.addItem(incoming_text, userData="incoming")

        layout.addWidget(choice_label)
        layout.addWidget(self._choice_combo)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self._on_reject)

        self._main_layout.addLayout(layout)
        self._main_layout.addWidget(button_box)

    def _on_accept(self):
        data = self._choice_combo.currentData(Qt.UserRole)
        self.selected_source = data or "current"
        self.accept()

    def _on_reject(self):
        self.reject()


def resolve_function_name_conflict(current_signature, incoming_signature, parent=None):
    """
    Open a dialog to resolve a single function name conflict.
    Returns one of "current", "incoming", or None if the dialog was cancelled.
    """
    dialog = FunctionNameMergeDialog(current_signature, incoming_signature, parent=parent)
    result = dialog.exec_()
    if result == QDialog.Accepted:
        return dialog.selected_source

    return None
