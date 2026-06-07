import getpass
import logging
import os
import time
from pathlib import Path
from typing import Optional

import filelock

from binsync.core.client import ConnectionWarnings, BINSYNC_ROOT_BRANCH
from binsync.configuration import BinSyncDLConfig, ProjectData
from declib.ui.qt_objects import (
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
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView
)
l = logging.getLogger(__name__)


class BSProjectDialog(QDialog):
    TITLE = "BS Project Dialog"

    def __init__(self, controller, parent=None):
        super().__init__(parent)
        # project information
        self.controller = controller
        self.configured = False
        self.username = None
        self.project_path = None
        # project options
        self.disable_push = False
        self.disable_pull = False

        self.setWindowTitle(self.TITLE)
        self._main_layout = QVBoxLayout()
        self._grid_layout = QGridLayout()
        self.row = 0

        self._init_username_widget()
        self._init_middle_widgets()
        self._main_layout.addLayout(self._grid_layout)

        self._init_option_widgets()
        self._init_close_btn_widgets()

        self.setLayout(self._main_layout)

    def _init_username_widget(self):
        username = getpass.getuser() or f"user_{int(time.time())}"
        user_label = QLabel(self)
        user_label.setText("Username")
        user_label.setToolTip(
            "The name your saves will be attributed to. Can be anything other that '__root__'. This name does not "
            "need to be the same as your Git username."
        )
        self._user_edit = QLineEdit(self)
        self._user_edit.setText(username)
        self._grid_layout.addWidget(user_label, self.row, 0)
        self._grid_layout.addWidget(self._user_edit, self.row, 1)
        self.row += 1

    def _init_middle_widgets(self):
        pass

    def _init_option_widgets(self):
        options_layout = QVBoxLayout()
        self._disable_push_checkbox = QCheckBox(self)
        self._disable_push_checkbox.setText("Disable auto-push to remote")
        self._disable_push_checkbox.setToolTip(
            "Disables BinSync git-backend to automatically push commits (saves) to the remote connected to "
            "the project. Use this if you plan on working on a cloned project offline."
        )
        self._disable_push_checkbox.setChecked(False)
        options_layout.addWidget(self._disable_push_checkbox)

        self._disable_pull_checkbox = QCheckBox(self)
        self._disable_pull_checkbox.setText("Disable auto-pull from remote")
        self._disable_pull_checkbox.setToolTip(
            "Disables BinSync git-backend to automatically pull commits (saves) from the remote connected to "
            "the project. Use this if you plan on working on a cloned project offline."
        )
        self._disable_pull_checkbox.setChecked(False)
        options_layout.addWidget(self._disable_pull_checkbox)

        self._disable_commit_checkbox = QCheckBox(self)
        self._disable_commit_checkbox.setText("Disable auto-commit")
        self._disable_commit_checkbox.setToolTip(
            "Disables BinSync git-backend to automatically commit changes to the project. Use this if you plan on "
            "working on a project and immediately running many changes you don't want recorded."
        )
        self._disable_commit_checkbox.setChecked(False)
        options_layout.addWidget(self._disable_commit_checkbox)

        self._main_layout.addLayout(options_layout)

    def _init_close_btn_widgets(self):
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

        self._main_layout.addLayout(buttons_layout)

    #
    # callbacks
    #

    def _on_ok_clicked(self):
        self.configured = True
        self.username = self._user_edit.text()
        self.disable_push = self._disable_push_checkbox.isChecked()
        self.disable_pull = self._disable_pull_checkbox.isChecked()
        self.disable_commit = self._disable_commit_checkbox.isChecked()
        self.close()

    def _on_cancel_clicked(self):
        self.close()


class CreateBSProjectDialog(BSProjectDialog):
    TITLE = "Create BS Project"

    def _init_middle_widgets(self):
        save_path = str(self._get_speculated_save_path())

        save_path_label = QLabel(self)
        save_path_label.setText("Save path")
        self._repo_edit = QLineEdit(self)
        self._repo_edit.setText(save_path)
        repo_button = QPushButton(self)
        repo_button.setText("...")
        repo_button.clicked.connect(self._on_repo_clicked)
        repo_button.setFixedWidth(40)

        self._grid_layout.addWidget(save_path_label, self.row, 0)
        self._grid_layout.addWidget(self._repo_edit, self.row, 1)
        self._grid_layout.addWidget(repo_button, self.row, 2)
        self.row += 1

        self._remote_edit = QLineEdit(self)
        self._grid_layout.addWidget(QLabel("Remote URL", parent=self), self.row, 0)
        self._grid_layout.addWidget(self._remote_edit, self.row, 1)
        self._grid_layout.addWidget(QLabel("(optional)", parent=self), self.row, 2)
        self.row += 1

    def _on_repo_clicked(self):
        path, _ = QFileDialog.getSaveFileName(self, caption="Select save location", filter=".bsproj")
        path = Path(path)
        if not path.name:
            l.info("No name specified for saved project. Using binary name...")
            try:
                filename = Path(self.controller.deci.binary_path).name
            except Exception as e:
                filename = str(int(time.time()))
                l.warning("Failed to grab binary name because %s. Maybe the decompiler is not ready for API use? "
                          "Using the timestamp instead: %s.bsproj", e, filename)

            filename += ".bsproj"
            path = path.absolute().joinpath(filename)

        if ".bsproj" not in path.name:
            path = path.with_suffix(".bsproj")

        self._repo_edit.setText(str(path))

    def _on_ok_clicked(self):
        self.project_path = self._repo_edit.text()
        self.remote_url = self._remote_edit.text()
        super()._on_ok_clicked()

    def _get_speculated_save_path(self):
        binary_path = self.controller.deci.binary_path
        if binary_path is not None:
            binary_path = Path(binary_path)

        if binary_path and binary_path.exists():
            return binary_path.with_suffix(".bsproj").absolute()

        working_dir = Path(os.getcwd())
        working_dir.joinpath(Path("my_project.bsproj"))
        return working_dir.absolute()


class OpenBSProjectDialog(BSProjectDialog):
    TITLE = "Open BS Project"

    def _init_middle_widgets(self):
        proj_path = QLabel(self)
        proj_path.setText("Project path")
        self._repo_edit = QLineEdit(self)
        self._repo_edit.textChanged.connect(self._on_repo_textchanged)
        repo_button = QPushButton(self)
        repo_button.setText("...")
        repo_button.clicked.connect(self._on_repo_clicked)
        repo_button.setFixedWidth(40)

        self._grid_layout.addWidget(proj_path, self.row, 0)
        self._grid_layout.addWidget(self._repo_edit, self.row, 1)
        self._grid_layout.addWidget(repo_button, self.row, 2)
        self.row += 1
        
        self._remote_edit = QLineEdit(self)
        self._grid_layout.addWidget(QLabel("Remote URL", parent=self), self.row, 0)
        self._grid_layout.addWidget(self._remote_edit, self.row, 1)
        self._grid_layout.addWidget(QLabel("(optional)", parent=self), self.row, 2)
        self.row += 1

    def _on_repo_clicked(self):
        flags = QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        if 'SNAP' in os.environ:
            flags |= QFileDialog.DontUseNativeDialog

        directory = QFileDialog.getExistingDirectory(self, "Select a BS Project", "", flags)
        self._repo_edit.setText(QDir.toNativeSeparators(directory))

    def _on_repo_textchanged(self, new_text):
        pass

    def _on_ok_clicked(self):
        self.project_path = self._repo_edit.text()
        self.remote_url = self._remote_edit.text()
        super()._on_ok_clicked()


class ConfigureBSDialog(QDialog):
    def __init__(self, controller, open_magic_sync=True, load_config=True, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.open_magic_sync = open_magic_sync
        self.load_config = load_config

        self.setWindowTitle("Start BinSync")
        self.resize(800, 400)
        self.setMinimumWidth(600)
        self._main_layout = QVBoxLayout()

        self._init_widgets()
        self.setLayout(self._main_layout)

    def _critical(self, title: str, text: str):
        """Show a critical error without creating a temporary QMessageBox.

        On macOS, allowing Python/Shiboken to GC temporary QMessageBox wrapper
        instances off the main thread can crash AppKit while tearing down the
        underlying NSWindow. Using the static helpers avoids that wrapper
        lifetime issue entirely.
        """
        QMessageBox.critical(self, title, text)

    def _question(self, title: str, text: str, buttons):
        return QMessageBox.question(self, title, text, buttons)

    def _init_widgets(self):
        upper_layout = QGridLayout()
        row = 0

        open_btn = QPushButton(self)
        open_btn.setText("Open")
        open_btn.clicked.connect(self.open_open_bs_proj_dialog)
        open_label = QLabel(self)
        open_label.setText("Open a BS project...")
        upper_layout.addWidget(open_btn, row, 0)
        upper_layout.addWidget(open_label, row, 1)
        row += 1

        new_btn = QPushButton(self)
        new_btn.setText("New")
        new_btn.clicked.connect(self.open_create_bs_proj_dialog)
        new_label = QLabel(self)
        new_label.setText("Create a new BS project...")
        upper_layout.addWidget(new_btn, row, 0)
        upper_layout.addWidget(new_label, row, 1)
        row += 1
        upper_layout.setVerticalSpacing(10)

        # table
        prev_proj_label = QLabel(self)
        prev_proj_label.setText("Previous Projects")
        upper_layout.addWidget(prev_proj_label, row, 0)
        prev_proj_layout = QHBoxLayout()
        self._prev_proj_table = QTableWidget(self)
        self._fill_table_with_configs()
        self._prev_proj_table.horizontalHeader().setStretchLastSection(True)
        self._prev_proj_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._prev_proj_table.verticalHeader().setVisible(False)
        self._prev_proj_table.horizontalHeader().setVisible(False)
        self._prev_proj_table.setMinimumHeight(120)
        self._prev_proj_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._prev_proj_table.itemDoubleClicked.connect(self._handle_prev_proj_double_click)
        prev_proj_layout.addWidget(self._prev_proj_table)

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
        self._main_layout.addLayout(prev_proj_layout)
        self._main_layout.addLayout(buttons_layout)

    def _fill_table_with_configs(self):
        top_confs = self.load_saved_config()

        if top_confs is None:
            self._prev_proj_table.setRowCount(1)
            self._prev_proj_table.setColumnCount(1)
            return

        self._prev_proj_table.setRowCount(len(top_confs))
        self._prev_proj_table.setColumnCount(1)

        for i, top_conf in enumerate(top_confs):
            self._prev_proj_table.setItem(i, 0, QTableWidgetItem(top_conf))
            self._prev_proj_table.selectRow(0)

    def _get_selected_config_row(self):
        items = self._prev_proj_table.selectedItems()
        if not items:
            return None, None

        item = items[0]
        username = None
        proj_path = None
        try:
            config_data = item.text()
            parts = config_data.split(":")
            username = parts[-1]
            proj_path = ":".join(parts[:-1])
        except Exception:
            l.warning("Config file is corrupted!")

        return username, proj_path

    def use_recent_project_config(self):
        username, proj_path = self._get_selected_config_row()
        if username is None:
            l.critical("Failed to grab the current user!")
            return False

        return self.connect_client_to_project(username, proj_path, initialize=False)

    #
    # Callbacks
    #

    def _on_cancel_clicked(self):
        self.close()

    def _on_ok_clicked(self):
        self.use_recent_project_config()
        self.close()

    def _handle_prev_proj_double_click(self):
        self.use_recent_project_config()
        self.close()

    #
    # Open or Create with external dialog
    #

    def open_create_bs_proj_dialog(self):
        self.open_or_create_from_dialog(create=True)

    def open_open_bs_proj_dialog(self):
        self.open_or_create_from_dialog(create=False)

    def open_or_create_from_dialog(self, create=False):
        dialog_cls = CreateBSProjectDialog if create else OpenBSProjectDialog
        dialog = dialog_cls(self.controller, parent=self)
        self.hide()
        dialog.exec_()
        self.show()
        if not dialog.configured:
            l.warning("Stopping configuration before connection...")
            return

        remote_url = None
        initialize = create
        project_path = Path(dialog.project_path) if dialog.project_path is not None else None
        username = dialog.username
        remote_url = dialog.remote_url if dialog.remote_url else None

        valid_config = True
        if not username or username.lower() == BINSYNC_ROOT_BRANCH:
            self._critical(
                "Invalid username",
                f"Username cannot be empty or be {BINSYNC_ROOT_BRANCH}"
            )
            valid_config = False

        if not create:
            if not remote_url:
                if not project_path.exists():
                    self._critical(
                        "Project does not exist",
                        "The specified BS project does not exist. "
                    )
                    valid_config = False

                if not self.is_git_repo(project_path):
                    self._critical(
                        "Directory contains no .git",
                        "The specified directory is not a BS project (it has no .git) "
                    )
                    valid_config = False
            else:
                if project_path.exists() and any(project_path.iterdir()):
                    self._critical(
                        "Directory Exists",
                        "The specified directory exists and is not empty, this should not be for remote cloning! "
                    )
                    valid_config = False

        if create and Path(project_path).exists():
            self._critical(
                "Project Exists",
                "The specified BS project already exists! You should open it instead. "
            )
            valid_config = False

        if not valid_config:
            l.warning("You did not provide a valid configuration, quiting...")
            return

        # by this point we know the data is valid data
        successs = self.connect_client_to_project(
            username, project_path, initialize=initialize, remote_url=remote_url,
            push_on_update=not dialog.disable_push, pull_on_update=not dialog.disable_pull,
            commit_on_update=not dialog.disable_commit
        )
        if not successs:
            l.critical("Failed to configure correctly, see above log.")

        self.close()

    #
    # Client helpers
    #

    def connect_client_to_project(self, username, proj_path, initialize=False, remote_url=None, push_on_update=True,
                                  pull_on_update=True, commit_on_update=True):
        # If this process is already connected to the same project, the lockfile
        # we'd see belongs to us — don't go through the delete-lockfile dance and
        # don't tear down/recreate the client (which corrupts Qt model state and
        # has crashed IDA in the past).
        existing_client = self.controller.client
        if existing_client is not None:
            try:
                existing_path = Path(existing_client.repo_root).resolve()
                requested_path = Path(proj_path).resolve()
            except Exception:
                existing_path = requested_path = None
            if existing_path is not None and existing_path == requested_path:
                l.info("Already connected to %s; skipping reconnect.", proj_path)
                return True

        lockfile_path = Path(proj_path) / ".git" / "binsync.lock"
        if lockfile_path.exists():
            repo_lock = filelock.FileLock(lockfile_path)
            try:
                repo_lock.acquire(timeout=0)
                lock_exists = False
            except filelock.Timeout:
                lock_exists = True

            if lock_exists:
                box_resp = self._question(
                    "Error",
                    "WARNING: Can only have one binsync client touching a local repository at once."
                    + "If the previous client crashed, the lockfile at:"
                    + f"'{lockfile_path.resolve()}'\n"
                    + "must be deleted. Would you like to delete this now?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if box_resp == QMessageBox.Yes:
                    lockfile_path.unlink()
            else:
                repo_lock.release()
        try:
            connection_warnings = self.controller.connect(
                username, str(proj_path), init_repo=initialize, remote_url=remote_url,
                push_on_update=push_on_update, pull_on_update=pull_on_update, commit_on_update=commit_on_update
            )
        except Exception as e:
            l.critical("Error connecting to specified repository: %s!", e)
            self._critical("Error connecting to repository", str(e))
            return False

        self.controller.auto_commit_enabled = commit_on_update
        self.controller.auto_pull_enabled = pull_on_update
        self.controller.auto_push_enabled = push_on_update
        self._parse_and_display_connection_warnings(connection_warnings, parent=self)
        l.info("Client has connected to sync repo with user: %s.", username)

        # create and save config if possible
        saved_config = self.save_config(username, proj_path, remote_url)
        if saved_config:
            l.debug("Configuration file was saved to %s.", saved_config)

        return True

    @staticmethod
    def is_git_repo(path: Path):
        return (path / ".git").exists()

    @staticmethod
    def _parse_and_display_connection_warnings(warnings, parent=None):
        warning_text = ""

        for warning in warnings:
            if warning == ConnectionWarnings.HASH_MISMATCH:
                warning_text += "Warning: the hash stored for this BinSync project does not match " \
                                "the hash of the binary you are attempting to analyze. It's possible " \
                                "you are working on a different binary.\n"

        if len(warning_text) > 0:
            QMessageBox.warning(
                parent,
                "BinSync: Connection Warnings",
                warning_text,
                QMessageBox.Ok,
            )

    def load_saved_config(self):
        binary_hash = self.controller.deci.binary_hash
        config = self.controller.load_saved_config()
        if not config or not isinstance(config, BinSyncDLConfig):
            return None

        if binary_hash not in config.recent_projects.keys():
            return None

        project_data_dicts = config.recent_projects[binary_hash]
        confs = []
        for project_state in project_data_dicts:
            project_data = ProjectData.get_from_state(project_state)
            user = project_data.user or ""
            repo = project_data.repo_path or ""

            # Drop entries whose repo no longer exists on disk so users don't
            # pick a stale path that will fail to open.
            if repo and not Path(repo).exists():
                continue

            if not user and not repo:
                confs.append(None)

            confs.append(f"{repo}:{user}")

        return confs or None

    def save_config(self, user, repo, remote) -> Optional[str]:
        if remote and not repo:
            repo = str(Path(self.controller.client.repo_root).absolute())

        if not self.controller.config:
            self.controller.config = BinSyncDLConfig()

        self.controller.config.save_project_data(
            self.controller.deci.binary_path,
            self.controller.deci.binary_hash,
            user=user,
            repo_path=repo,
            remote=remote
        )

        return self.controller.config.save()
