import logging
import os
import time
import pathlib
import traceback
from typing import Optional
import git

import toml
from binsync.core.client import ConnectionWarnings, BINSYNC_ROOT_BRANCH
from binsync.data.configuration import ProjectConfig
from binsync.common.ui.qt_objects import (
    QCheckBox,
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
)

l = logging.getLogger(__name__)

class SyncConfig(QDialog):
    """
    The dialog that allows a user to config a BinSync client for:
    - initing a local repo
    - cloning a remote
    - using a locally pulled remote repo
    """
    def __init__(self, controller, open_magic_sync=True, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.open_magic_sync = open_magic_sync
        self.setWindowTitle("Configure BinSync")

        self._main_layout = QVBoxLayout()
        self._user_edit = None  # type:QLineEdit
        self._repo_edit = None  # type:QLineEdit
        self._remote_edit = None  # type:QLineEdit
        self._initrepo_checkbox = None  # type:QCheckBox

        self._init_widgets()
        self.setLayout(self._main_layout)
        self.show()

    def _init_widgets(self):
        upper_layout = QGridLayout()

        # user label
        user_label = QLabel(self)
        user_label.setText("User name")
        user_label.setToolTip(
            "The name your user will be saved as on remote. Can be anything other that 'root'. This name does not "
            "need to be the same as your Git username."
        )

        self._user_edit = QLineEdit(self)

        row = 0
        upper_layout.addWidget(user_label, row, 0)
        upper_layout.addWidget(self._user_edit, row, 1)
        row += 1

        # binsync label
        binsync_label = QLabel(self)
        binsync_label.setText("Git repo")
        binsync_label.setToolTip(
            "The path to a locally cloned Git repo. This can be ignored if you have not cloned down a remote "
            "repo yet, but you have the URL. The local repo can also be an empty folder that will be turned into "
            "a BinSync database by selecting 'init_remote'."
        )

        # repo path
        self._repo_edit = QLineEdit(self)
        self._repo_edit.textChanged.connect(self._on_repo_textchanged)
        #self._repo_edit.setFixedWidth(150)

        # repo path selection button
        repo_button = QPushButton(self)
        repo_button.setText("...")
        repo_button.clicked.connect(self._on_repo_clicked)
        repo_button.setFixedWidth(40)

        upper_layout.addWidget(binsync_label, row, 0)
        upper_layout.addWidget(self._repo_edit, row, 1)
        upper_layout.addWidget(repo_button, row, 2)
        row += 1

        # clone from a remote URL
        self.remote_label = QLabel(self)
        self.remote_label.setText("Remote URL")
        self.remote_label.setToolTip(
            "The URL to a remove Git repo. This is not required if you have already selected a locally cloned "
            "Git repo that has a remote. This repo will be cloned to the same location as your binary if a local "
            "repo does not exist yet."
        )


        self._remote_edit = QLineEdit(self)

        upper_layout.addWidget(self.remote_label, row, 0)
        upper_layout.addWidget(self._remote_edit, row, 1)
        row += 1

        # initialize repo checkbox
        self._initrepo_checkbox = QCheckBox(self)
        self._initrepo_checkbox.setText("Init Remote")
        self._initrepo_checkbox.setToolTip(
            "Ether inits the local folder, making it into a Git repo, or updates the remote references of the current "
            "Git repo to have the correct BinSync layout which includes the root branch and the new user. Should only "
            "ever be used when first creating a BinSync repo for all users."
        )
        self._initrepo_checkbox.setChecked(False)
        #self._initrepo_checkbox.setEnabled(False)

        upper_layout.addWidget(self._initrepo_checkbox, row, 1)
        row += 1

        # buttons
        self._ok_button = QPushButton(self)
        self._ok_button.setText("OK")
        self._ok_button.setDefault(True)
        self._ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(cancel_button)

        # main layout
        self._main_layout.addLayout(upper_layout)
        self._main_layout.addLayout(buttons_layout)

        # change the text if config exists
        self.load_saved_config()

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        user = self._user_edit.text()
        path = self._repo_edit.text()
        remote_url = self._remote_edit.text()
        init_repo = self._initrepo_checkbox.isChecked()

        l.debug("Attempting to connect to/init repo, user: %s | path: %s | init_repo? %r", user, path, init_repo)

        if not user:
            QMessageBox(self).critical(None, "Invalid user name",
                                       "User name cannot be empty."
                                       )
            return

        if user.lower() == "__root__":
            QMessageBox(self).critical(None, "Invalid user name",
                                       "User name cannot (and should not) be \'__root__\'."
                                       )
            return

        if not remote_url and not os.path.isdir(path) and not init_repo:
            QMessageBox(self).critical(None, "Repo does not exist",
                                       "The specified sync directory does not exist. "
                                       "Do you maybe want to initialize it?"
                                       )
            return

        # convert to remote repo if no local is provided
        if self.is_git_repo(path):
            remote_url = None

        if remote_url and not path:
            path = os.path.join(os.path.dirname(self.controller.binary_path() or ""),
                                os.path.basename(self.controller.binary_path() or "") + "_bs"
                                )

        try:
            connection_warnings = self.controller.connect(user, path, init_repo=init_repo, remote_url=remote_url)
            pass
        except Exception as e:
            l.critical("Error connecting to specified repository!")
            QMessageBox(self).critical(None, "Error connecting to repository", str(e))
            traceback.print_exc()
            return

        #
        # controller is now successfully connected to a real BinSync client. Everything from this point
        # onwards assumes that all normal client properties and functions work.
        #

        # warn user of anything that might look off
        self._parse_and_display_connection_warnings(connection_warnings)
        l.info(f"Client has connected to sync repo with user: {user}.")

        # create and save config if possible
        saved_config = self.save_config()
        if saved_config:
            l.debug(f"Configuration file was saved to {saved_config}.")

        self.close()

    def _on_repo_clicked(self):
        if 'SNAP' in os.environ:
            directory = QFileDialog.getExistingDirectory(self, "Select sync repo", "",
                                                    QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks | QFileDialog.DontUseNativeDialog)
        else:
            directory = QFileDialog.getExistingDirectory(self, "Select sync repo", "",
                                                         QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
        self._repo_edit.setText(QDir.toNativeSeparators(directory))

    def _on_repo_textchanged(self, new_text):
        path = new_text
        if pathlib.Path(path).exists() and self.is_git_repo(path):
            repo = git.Repo(path)
            try:
                url = repo.remote().url
            except Exception:
                url = None

            self._remote_edit.setText(url or "")
            self._remote_edit.setEnabled(False)
            self.remote_label.setStyleSheet('color: gray')

            is_binsync_inited = False
            try:
                is_binsync_inited = any(ref.name.endswith(BINSYNC_ROOT_BRANCH) for ref in repo.remote().refs)
            except Exception:
                pass

            if is_binsync_inited:
                self._initrepo_checkbox.setChecked(False)
                self._initrepo_checkbox.setStyleSheet(
                    'QCheckBox::unchecked { color: gray } '
                    'QCheckBox::checked { color: gray }'
                )
                self._initrepo_checkbox.setEnabled(False)
            else:
                self._initrepo_checkbox.setEnabled(True)
                self._initrepo_checkbox.setStyleSheet(
                    'QCheckBox::unchecked { color: white } '
                    'QCheckBox::checked { color: white }'
                )
        else:
            self.remote_label.setStyleSheet('color: white')

    def _on_cancel_clicked(self):
        self.close()

    #
    # Utils
    #

    def load_saved_config(self) -> bool:
        config = ProjectConfig.load_from_file(self.controller.binary_path() or "")
        if not config:
            return False

        user = config.user or ""
        repo = config.repo_path or ""
        remote = config.remote if config.remote and not config.repo_path else ""

        self._user_edit.setText(user)
        self._repo_edit.setText(repo)
        self._on_repo_textchanged(repo)
        self._remote_edit.setText(remote)
        return True

    def save_config(self) -> Optional[str]:
        user = self._user_edit.text()
        remote = self._remote_edit.text()
        repo = self._repo_edit.text()

        if remote and not repo:
            repo = str(pathlib.Path(self.controller.client.repo_root).absolute())

        config = ProjectConfig(
            self.controller.binary_path() or "",
            user=user,
            repo_path=repo,
            remote=remote
        )
        if not config:
            return config

        return config.save()


    #
    # Static methods
    #

    @staticmethod
    def is_git_repo(path):
        return os.path.isdir(os.path.join(path, ".git"))

    @staticmethod
    def _parse_and_display_connection_warnings(warnings):
        warning_text = ""

        for warning in warnings:
            if warning == ConnectionWarnings.HASH_MISMATCH:
                warning_text += "Warning: the hash stored for this BinSync project does not match " \
                                "the hash of the binary you are attempting to analyze. It's possible " \
                                "you are working on a different binary.\n"

        if len(warning_text) > 0:
            QMessageBox.warning(
                None,
                "BinSync: Connection Warnings",
                warning_text,
                QMessageBox.Ok,
            )
