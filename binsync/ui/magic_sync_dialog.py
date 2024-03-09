import logging

from libbs.ui.qt_objects import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QVBoxLayout,
    QLabel,
    QComboBox,
    Qt
)


l = logging.getLogger(__name__)


class MagicSyncDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

        self.setWindowTitle("Magic Sync")
        self._main_layout = QGridLayout()
        self._init_widgets()
        self.setLayout(self._main_layout)

        self.should_sync = False
        self.preferred_user = None
        self.show()

    def _init_widgets(self):
        vertical_layout = QVBoxLayout()

        # dialog text
        self.label = QLabel(self)
        self.label.setWordWrap(True)
        self.label.setText(
            "<html><head/><body><p> Magic Sync is a one-time sync that attempts to sync <span style=\" "
            "font-weight:600;\">non-conflicting</span> data from all users on all functions, essentially a global "
            "knowledge merge. Would you like to preform this action? You may optionally select a user you would like "
            "prioritized for non-conflicting sync first.</p><p>Priority User:</p></body></html>",
        )

        # user selection
        items = self._get_users()
        self.comboBox = QComboBox(self)
        self.comboBox.addItems(items)

        # confirm button
        self.buttonBox = QDialogButtonBox(self)
        self.buttonBox.setStandardButtons(QDialogButtonBox.No | QDialogButtonBox.Yes)
        self.buttonBox.accepted.connect(self._on_yes_clicked)
        self.buttonBox.rejected.connect(self._on_no_clicked)

        vertical_layout.addWidget(self.label, 0, Qt.AlignBottom)
        vertical_layout.addWidget(self.comboBox, 0, Qt.AlignBottom)
        vertical_layout.addWidget(self.buttonBox, 0, Qt.AlignBottom)

        self._main_layout.addLayout(vertical_layout, 0, 0, 1, 1)

    def _get_users(self):
        return ["None"] + list(self.controller.usernames(priority=1))

    def _on_yes_clicked(self):
        self.should_sync = True
        combo_text = self.comboBox.currentText()
        self.preferred_user = combo_text if combo_text != "None" else None
        self.close()

    def _on_no_clicked(self):
        self.should_sync = False
        self.close()


def display_magic_sync_dialog(controller):
    dialog = MagicSyncDialog(controller)
    dialog.exec_()

    if not dialog.should_sync:
        return

    controller.magic_fill(preference_user=dialog.preferred_user)
