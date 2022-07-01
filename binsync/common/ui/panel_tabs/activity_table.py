import logging
from typing import Dict

from binsync.common.controller import BinSyncController
from binsync.common.ui.qt_objects import (
    QAbstractItemView,
    QHeaderView,
    QMenu,
    Qt,
    QTableWidget,
    QTableWidgetItem,
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
from binsync.data import Function
from binsync.core.scheduler import SchedSpeed
from binsync.data.state import State

l = logging.getLogger(__name__)

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
        menu.setObjectName("binsync_activity_table_context_menu")

        selected_row = self.rowAt(event.pos().y())
        item = self.item(selected_row, 0)
        if item is None:
            return
        username = item.text()
        menu.addAction("Sync", lambda: self.controller.fill_function(self.item(selected_row, 1).data(Qt.UserRole), user=username))

        menu.addAction("Sync-All", lambda: self.controller.fill_all(user=username))

        for_menu = menu.addMenu("Sync for...")
        for func_addr_str in self._get_valid_funcs_for_user(username):
            for_menu.addAction(func_addr_str, lambda: self.controller.fill_function(int(func_addr_str, 16), user=username))

        menu.popup(self.mapToGlobal(event.pos()))

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
                if not sync_func.last_change:
                    continue

                # check if we already know about it
                if func_addr in changed_funcs:
                    # compare this users change time to the store change time
                    if not func_change_time or func_change_time < changed_funcs[func_addr]:
                        continue

                changed_funcs[func_addr] = func_change_time

            if len(changed_funcs) > 0:
                most_recent_func = list(changed_funcs)[0]
                last_state_change = state.last_push_time \
                    if not state.last_push_time \
                    else list(changed_funcs.values())[0]
            else:
                most_recent_func = ""
                last_state_change = state.last_push_time

            self.items.append(
                QActivityItem(user.name, most_recent_func, last_state_change)
            )

    def _get_valid_funcs_for_user(self, username):
        user_state: State = self.controller.client.get_state(user=username, priority=SchedSpeed.FAST)
        func_addrs = [addr for addr in user_state.functions]

        func_addrs.sort()
        for func_addr in func_addrs:
            yield hex(func_addr)
