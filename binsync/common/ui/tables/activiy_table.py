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
from ....data import Function


class QActivityItem:
    def __init__(self, user, activity, last_push):
        self.user = user
        self.activity = activity
        self.last_push = last_push

    def widgets(self):
        if isinstance(self.activity, int):
            activity = QNumericItem(hex(self.activity))
            activity.setData(Qt.UserRole, self.activity)
        else:
            activity = QNumericItem(self.activity)
            # set to max number so its last
            activity.setData(Qt.UserRole, -1)

        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            user,
            activity,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QActivityTable(QTableWidget):
    """
    The activity table shown in the Control Panel. This table is responsible for showing users information
    that is relevant to other users activity. The main user wants to know what others are doing, and how
    often they are doing it. This table should also allow users to sync from a user if they see them as
    being very active.

    TODO: refactor the below code to allow activity view to show any item, not just a function!
    """

    HEADER = [
        'User',
        'Activity',
        'Last Push'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QActivityTable, self).__init__(parent)
        self.controller = controller
        self.items = []

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
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
        selected_row = self.columnAt(event.pos().y())
        username = self.item(selected_row, 0).text()
        for_menu = menu.addMenu("Sync for...")
        for func_addr_str in self._get_valid_funcs_for_user(username):
            for_menu.addAction(func_addr_str)

        # execute the event
        action = menu.exec_(self.mapToGlobal(event.pos()))

        if action == sync_action:
            activity_item = self.item(selected_row, 1).data(Qt.UserRole)
        elif action in for_menu.actions():
            activity_item = int(action.text(), 16)
        else:
            return

        self.controller.fill_function(activity_item, user=username)

    def update_table(self):
        self.items = []

        # first check if any functions are unknown to the table
        for user in self.controller.users():
            changed_funcs = {}
            state = self.controller.client.get_state(user=user.name)
            user_funcs: Dict[int, Function] = state.functions

            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change

                # don't add functions that were never changed by the user
                if sync_func.last_change == -1:
                    continue

                # check if we already know about it
                if func_addr in changed_funcs:
                    # compare this users change time to the store change time
                    if func_change_time < changed_funcs[func_addr]:
                        continue

                changed_funcs[func_addr] = func_change_time

            if len(changed_funcs) > 0:
                most_recent_func = list(changed_funcs)[0]
                last_state_change = state.last_push_time \
                    if state.last_push_time != -1 \
                    else list(changed_funcs.values())[0]
            else:
                most_recent_func = ""
                last_state_change = state.last_push_time

            self.items.append(
                QActivityItem(user.name, most_recent_func, last_state_change)
            )

        self.reload()

    def _get_valid_funcs_for_user(self, username):
        user_state: State = self.controller.client.get_state(user=username)
        func_addrs = [addr for addr in user_state.functions]

        func_addrs.sort()
        for func_addr in func_addrs:
            yield hex(func_addr)
