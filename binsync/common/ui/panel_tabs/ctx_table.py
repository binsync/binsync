import logging

from .. import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PySide2.QtCore import Qt
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PySide6.QtCore import Qt
else:
    from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PyQt5.QtCore import Qt

from ..utils import QNumericItem, friendly_datetime
from ...controller import BinSyncController

l = logging.getLogger(__name__)

class QCTXItem:
    """
    The CTX view shown in the Control Panel. Responsible for showing the main user info on whatever the main user
    is currently looking at (clicked). For any line in a function, this would be the entire function. For a struct,
    this would be a struct. The view will be as useful as the decompilers support for understanding what the user
    is looking at.

    TODO: refactor this to allow for any context item, not just functions (like structs).
    """
    def __init__(self, user, name, last_push, changes):
        self.user = user
        self.name = name
        self.last_push = last_push
        self.changes = changes

    def widgets(self):
        user = QTableWidgetItem(self.user)
        name = QTableWidgetItem(self.name)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        changes = QNumericItem(self.changes)
        changes.setData(Qt.UserRole, self.changes)

        widgets = [
            user,
            name,
            last_push,
            changes
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QCTXTable(QTableWidget):

    HEADER = [
        'User',
        'Remote Name',
        'Last Push',
        'Changes'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QCTXTable, self).__init__(parent)
        self.controller = controller
        self.items = []
        self.ctx = None

        # header
        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignHCenter | Qt.Alignment(Qt.TextWordWrap))
        self.horizontalHeader().setMinimumWidth(160)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.setSortingEnabled(True)

    def reload(self):
        self.setSortingEnabled(False)
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()
        self.setSortingEnabled(True)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_context_table_context_menu")
        
        func_addr = self.ctx if self.ctx else None
        selected_row = self.rowAt(event.pos().y())
        item = self.item(selected_row, 0)
        if item is None:
            return
        username = item.text()
        menu.addAction("Sync", lambda: self.controller.fill_function(func_addr, user=username))

        menu.popup(self.mapToGlobal(event.pos()))


    def update_table(self, new_ctx=None):
        # only functions currently supported
        if self.ctx is None and new_ctx is None:
            return

        self.ctx = new_ctx or self.ctx
        self.items = []
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)

            func = state.get_function(self.ctx)

            if not func or not func.last_change:
                continue

            # changes is not currently supported
            self.items.append(
                QCTXItem(user.name, func.name, func.last_change, 0)
            )
