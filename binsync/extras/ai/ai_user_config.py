import os
from pathlib import Path
import logging

from binsync.ui.qt_objects import (
    QComboBox,
    QDialog,
    QDir,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView
)
from binsync.extras.ai.openai_bs_user import OpenAIBSUser, add_openai_user_to_project
from binsync.api.controller import BSController
from binsync.decompilers import ANGR_DECOMPILER, IDA_DECOMPILER

_l = logging.getLogger(__name__)

class AIUserConfigDialog(QDialog):
    TITLE = "AI User Configuration"

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self.api_key = os.getenv("OPENAI_API_KEY") or ""
        self.username = OpenAIBSUser.DEFAULT_USERNAME
        self.project_path = str(Path(controller.client.repo_root).absolute())
        self.binary_path = str(Path(controller.binary_path()).absolute()) if controller.binary_path() else ""
        self.base_on = ""

        self.setWindowTitle(self.TITLE)
        self._main_layout = QVBoxLayout()
        self._grid_layout = QGridLayout()
        self.row = 0

        self._init_widgets()
        self._main_layout.addLayout(self._grid_layout)
        self.setLayout(self._main_layout)

    def _init_widgets(self):
        # api key label
        self._api_key_label = QLabel("API Key")
        self._grid_layout.addWidget(self._api_key_label, self.row, 0)
        # api key input
        self._api_key_input = QLineEdit(self.api_key)
        self._grid_layout.addWidget(self._api_key_input, self.row, 1)
        self.row += 1

        # username label
        self._username_label = QLabel("Username")
        self._grid_layout.addWidget(self._username_label, self.row, 0)
        # username input
        self._username_input = QLineEdit(self.username)
        self._grid_layout.addWidget(self._username_input, self.row, 1)
        self.row += 1

        # binary label
        self._binary_path_label = QLabel("Binary Path")
        self._grid_layout.addWidget(self._binary_path_label, self.row, 0)
        # binary input
        self._binary_path_input = QLineEdit(self.binary_path)
        self._grid_layout.addWidget(self._binary_path_input, self.row, 1)
        # project button
        self._binary_path_button = QPushButton("...")
        self._binary_path_button.clicked.connect(self._on_binary_path_button_blocked)
        self._grid_layout.addWidget(self._binary_path_button, self.row, 2)
        self.row += 1

        # decompiler dropdown selection
        self._decompiler_label = QLabel("Decompiler Backend")
        self._grid_layout.addWidget(self._decompiler_label, self.row, 0)
        self._decompiler_dropdown = QComboBox()
        # TODO: add more decompilers
        self._decompiler_dropdown.addItems([ANGR_DECOMPILER])
        self._grid_layout.addWidget(self._decompiler_dropdown, self.row, 1)
        self.row += 1

        # user_base dropdown selection
        self._user_base_label = QLabel("Base On")
        self._grid_layout.addWidget(self._user_base_label, self.row, 0)
        self._user_base_dropdown = QComboBox()

        all_users = [user.name for user in self._controller.users()]
        curr_user = self._controller.client.master_user
        all_users.remove(curr_user)
        all_users = [curr_user] + all_users + [""]
        self._user_base_dropdown.addItems(all_users)
        self._grid_layout.addWidget(self._user_base_dropdown, self.row, 1)
        self.row += 1

        # ok/cancel buttons
        self._ok_button = QPushButton("OK")
        self._ok_button.clicked.connect(self._on_ok_button_clicked)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self._on_cancel_button_clicked)
        self._button_layout = QHBoxLayout()
        self._button_layout.addWidget(self._ok_button)
        self._button_layout.addWidget(self._cancel_button)

        self._main_layout.addLayout(self._grid_layout)
        self._main_layout.addLayout(self._button_layout)

    def _on_binary_path_button_blocked(self):
        # get the path to the binary
        binary_path = QFileDialog.getOpenFileName(self, "Select Binary", QDir.homePath())
        if binary_path[0]:
            self._binary_path_input.setText(binary_path[0])

    def _on_ok_button_clicked(self):
        self.api_key = self._api_key_input.text()
        self.binary_path = self._binary_path_input.text()
        self.username = self._username_input.text()
        self.decompiler_backend = self._decompiler_dropdown.currentText()
        self.base_on = self._user_base_dropdown.currentText()

        if not (self.api_key and self.binary_path and self.username):
            _l.critical("You did not provide a path, username, and API key for the AI user.")
            return

        _l.info(f"Starting AI user now! Commits from user {self.username} should appear soon...")
        add_openai_user_to_project(
            self.api_key, self.binary_path, self.project_path, username=self.username,
            base_on=self.base_on, headless=True, copy_proj=True
        )
        self.close()

    def _on_cancel_button_clicked(self):
        self.close()

