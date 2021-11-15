from typing import Dict

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
from .... import State
from ....data import Struct


class QGlobalItem:
    def __init__(self, name, type_, user, last_push):
        self.name = name
        self.type = type_
        self.user = user
        self.last_push = last_push

    def widgets(self):
        # sort by int value
        name = QTableWidgetItem(self.name)
        type_ = QTableWidgetItem(self.type)
        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            name,
            type_,
            user,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QGlobalsTable(QTableWidget):

    HEADER = [
        'Name',
        'Type',
        'User',
        'Last Push'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QGlobalsTable, self).__init__(parent)
        self.controller = controller
        self.items = []

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
        sync_action = menu.addAction("Sync")

        # create a nested menu
        selected_row = self.rowAt(event.pos().y())
        global_name = self.item(selected_row, 0).text()
        from_menu = menu.addMenu("Sync from...")
        for username in self._get_valid_users_for_global(global_name):
            from_menu.addAction(username)

        # execute the event
        action = menu.exec_(self.mapToGlobal(event.pos()))

        if action == sync_action:
            username = self.item(selected_row, 2).text()
        elif action in from_menu.actions():
            username = action.text()
        else:
            return

        #TODO: update for any global, not just struct
        self.controller.fill_struct(global_name, user=username)

    def update_table(self):
        known_structs = {}  # struct_name: (struct_name, name, user_name, push_time)

        # first check if any functions are unknown to the table
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_structs: Dict[str, Struct] = state.structs

            for struct_name, sync_struct in user_structs.items():
                struct_change_time = sync_struct.last_change

                # don't add functions that were never changed by the user
                if sync_struct.last_change == -1:
                    continue

                # check if we already know about it
                if struct_name in known_structs:
                    # compare this users change time to the store change time
                    if struct_change_time < known_structs[struct_name][3]:
                        continue

                known_structs[struct_name] = [struct_name, "Struct", user.name, struct_change_time]

        self.items = [QGlobalItem(*row) for row in known_structs.values()]

    def _get_valid_users_for_global(self, global_name):
        for user in self.controller.users():
            user_state: State = self.controller.client.get_state(user=user.name)

            try:
                user_global = user_state.get_struct(global_name)
            except KeyError:
                continue

            # function must be changed by this user
            if user_global.last_change == -1:
                continue

            yield user.name
