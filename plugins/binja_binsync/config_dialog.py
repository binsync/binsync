import os

from PySide2.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QHBoxLayout, QLabel, QPushButton, QGroupBox, \
    QMessageBox, QCheckBox
from binaryninja.interaction import get_directory_name_input

from .ui import BinjaWidget


class ConfigDialog(QDialog):
    def __init__(self, controller):
        super().__init__()

        self._w = None
        self._controller = controller

        self.setWindowTitle("BinSync")

        self._init_widgets()

    def _init_widgets(self):
        self._w = ConfigWidget(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class ConfigWidget(BinjaWidget):
    def __init__(self, controller, dialog):
        super().__init__("BinSync")

        self._funcaddr_edit = None  # type: QLineEdit
        self._controller = controller
        self._dialog = dialog

        self._init_widgets()

    def _init_widgets(self):

        #
        # Config
        #

        # user label
        user_label = QLabel(self)
        user_label.setText("User name")

        self._user_edit = QLineEdit(self)
        self._user_edit.setText("user0_binja")

        user_layout = QHBoxLayout()
        user_layout.addWidget(user_label)
        user_layout.addWidget(self._user_edit)

        # binsync label
        binsync_label = QLabel(self)
        binsync_label.setText("Git repo")

        # repo path
        self._repo_edit = QLineEdit(self)

        # select_button
        select_dir_button = QPushButton(self)
        select_dir_button.setText("...")
        select_dir_button.clicked.connect(self._on_dir_select_clicked)

        # layout
        repo_layout = QHBoxLayout()
        repo_layout.addWidget(binsync_label)
        repo_layout.addWidget(self._repo_edit)
        repo_layout.addWidget(select_dir_button)

        checkbox_layout = QHBoxLayout()
        init_repo_label = QLabel(self)
        init_repo_label.setText("Initialize repo")
        checkbox_layout.addWidget(init_repo_label)
        self._initrepo_checkbox = QCheckBox(self)
        self._initrepo_checkbox.setToolTip(
            "I'm the first user of this sync repo and I'd like to initialize it as a new repo."
        )
        self._initrepo_checkbox.setChecked(False)
        self._initrepo_checkbox.setEnabled(True)
        checkbox_layout.addWidget(self._initrepo_checkbox)

        # buttons
        connect_button = QPushButton(self)
        connect_button.setText("Connect")
        connect_button.clicked.connect(self._on_connect_clicked)
        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(connect_button)
        buttons_layout.addWidget(cancel_button)

        config_box = QGroupBox()
        config_box.setTitle("Configuration")
        config_layout = QVBoxLayout()
        config_layout.addLayout(user_layout)
        config_layout.addLayout(repo_layout)
        config_layout.addLayout(checkbox_layout)
        config_layout.addLayout(buttons_layout)
        config_box.setLayout(config_layout)

        # main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(config_box)

        self.setLayout(main_layout)

    def _on_dir_select_clicked(self):
        dirpath = get_directory_name_input("Select Git Root Directory")
        if isinstance(dirpath, bytes):
            dirpath = dirpath.decode("utf-8")  # TODO: Use the native encoding on Windows
        self._repo_edit.setText(dirpath)

    def _on_connect_clicked(self):
        user = self._user_edit.text()
        path = self._repo_edit.text()
        init_repo = self._initrepo_checkbox.isChecked()

        if not user:
            QMessageBox(self).critical(
                None, "Invalid user name", "User name cannot be empty."
            )
            return

        if not os.path.isdir(path):
            QMessageBox(self).critical(
                None, "Repo does not exist", "The specified sync repo does not exist."
            )
            return

        # TODO: Add a user ID to angr management
        self._controller.connect(user, path, init_repo)

        if self._dialog is not None:
            self._dialog.close()
        else:
            self.close()

    def _on_cancel_clicked(self):
        if self._dialog is not None:
            self._dialog.close()
        else:
            self.close()