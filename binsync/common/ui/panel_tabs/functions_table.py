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
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)

class QFunctionItem:
    def __init__(self, addr, name, user, last_push):
        self.addr = addr
        self.name = name
        self.user = user
        self.last_push = last_push

    def __eq__(self, other):
        return self.addr == other.addr

    def __hash__(self):
        return self.addr

    def widgets(self):
        # sort by int value
        addr = QNumericItem(hex(self.addr))
        addr.setData(Qt.UserRole, self.addr)

        name = QTableWidgetItem(self.name)
        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            addr,
            name,
            user,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QFunctionTable(QTableWidget):

    HEADER = [
        'Addr',
        'Remote Name',
        'User',
        'Last Push'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QFunctionTable, self).__init__(parent)
        self.controller = controller
        self.items = dict()

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
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

        self.doubleClicked.connect(self._doubleclick_handler)
        self.last_table = set()

    def reload(self):
        self.setSortingEnabled(False)
        self.setRowCount(len(self.items))
        new_table = set(self.items.values())
        new_entries = new_table.difference(self.last_table)

        for idx, item in enumerate(new_entries):
            for i, attr in enumerate(item.widgets()):
                self.setItem(idx, i, attr)

        self.last_table = new_table
        self.viewport().update()
        self.setSortingEnabled(True)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_function_table_context_menu")

        selected_row = self.rowAt(event.pos().y())
        item = self.item(selected_row, 0)
        if item is None:
            return
        func_addr = item.data(Qt.UserRole)
        
        menu.addAction("Sync", lambda: self.controller.fill_function(func_addr, user=self.item(selected_row, 2).text()))
        from_menu = menu.addMenu("Sync from...")
        
        for username in self._get_valid_users_for_func(func_addr):
            action = from_menu.addAction(username)
            action.triggered.connect(lambda chck, name=username: self.controller.fill_function(func_addr, user=name))  

        menu.popup(self.mapToGlobal(event.pos()))

    def update_table(self):
        known_funcs = {}  # addr: (addr, name, user_name, push_time)

        # first check if any functions are unknown to the table
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_funcs: Dict[int, Function] = state.functions

            for func_addr, sync_func in user_funcs.items():
                # don't add functions that were never changed by the user
                if not sync_func.last_change:
                    continue

                func_change_time = sync_func.last_change
                # check if we already know about it
                if func_addr in known_funcs:

                    # compare this users change time to the store change time
                    if not func_change_time or func_change_time < known_funcs[func_addr][3]:
                        continue
                remote_func_name = sync_func.name if sync_func.name else ""
                self.items[func_addr] = QFunctionItem(func_addr, remote_func_name, user.name, func_change_time)

    def _get_valid_users_for_func(self, func_addr):
        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            user_func = user_state.get_function(func_addr)

            # function must be changed by this user
            if not user_func or not user_func.last_change:
                continue

            yield user.name

    def _doubleclick_handler(self):
        # Doubleclick only allows for a single item select so just take first one from list
        row_idx = self.selectionModel().selectedIndexes()[0].row()
        row_addr = self.item(row_idx, 0).data(Qt.UserRole)
        self.controller.goto_address(row_addr)