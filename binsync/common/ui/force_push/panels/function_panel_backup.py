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
    QAction,
    QFontDatabase,
    QCheckBox
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
from binsync.data import Function

l = logging.getLogger(__name__)

fixed_width_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
fixed_width_font.setPointSize(11)

#TODO: table reloads cause selected item to randomly change? (only if sort changes)

class QFunctionItem:
    def __init__(self, addr, name, user, last_push):
        self.addr = addr
        self.name = name
        self.user = user
        self.last_push = last_push

    def widgets(self):
        #checked = QCheckBox("")
	
        # sort by int value
        #addr = QNumericItem(hex(self.addr))
        #addr.setData(Qt.UserRole, self.addr)

        addr = QCheckBox(hex(self.addr))
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

        for w in widgets[1:]:
            w.setFont(fixed_width_font)
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
        self.items = []

        self.setColumnCount(len(self.HEADER))
        self.column_visibility = [True for _ in range(len(self.HEADER))]
        self.setHorizontalHeaderLabels(self.HEADER)

        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignHCenter | Qt.Alignment(Qt.TextWordWrap))
        self.horizontalHeader().setMinimumWidth(160)
        self.horizontalHeader().setSortIndicator(0, Qt.AscendingOrder)

        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(22)

        self.setSortingEnabled(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)

    def reload(self):
        self.setSortingEnabled(False)
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                if i==0:
                    self.setCellWidget(idx, i, it) 
                else:
                    self.setItem(idx, i, it)

        self.viewport().update()
        self.setSortingEnabled(True)

    def update_table(self):
        known_funcs = {}  # addr: (addr, name, user_name, push_time)

        # first check if any functions are unknown to the table
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_funcs: Dict[int, Function] = state.functions

            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change

                # don't add functions that were never changed by the user
                if not sync_func.last_change:
                    continue

                # check if we already know about it
                if func_addr in known_funcs:
                    # compare this users change time to the store change time
                    if not func_change_time or func_change_time < known_funcs[func_addr][3]:
                        continue

                remote_func_name = sync_func.name if sync_func.name else ""
                known_funcs[func_addr] = [func_addr, remote_func_name, user.name, func_change_time]

        self.items = [QFunctionItem(*row) for row in known_funcs.values()]

    def _get_valid_users_for_func(self, func_addr):
        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            user_func = user_state.get_function(func_addr)

            # function must be changed by this user
            if not user_func or not user_func.last_change:
                continue

            yield user.name
