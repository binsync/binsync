import logging
import time
from typing import Dict
import datetime

from binsync.common.controller import BinSyncController
from binsync.common.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from binsync.common.ui.qt_objects import (
    QMenu,
    QAction,
    QWidget,
    QVBoxLayout,
    QColor,
    Qt
)
from binsync.common.ui.utils import friendly_datetime
from binsync.core.scheduler import SchedSpeed
from binsync.data import Function

l = logging.getLogger(__name__)


class ActivityTableModel(BinsyncTableModel):
    def __init__(self, controller: BinSyncController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.saved_color_window = self.controller.table_coloring_window
        self.context_menu_cache = {}

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        if role == Qt.DisplayRole:
            if col == 0:
                return self.row_data[index.row()][col]
            elif col == 1:
                return hex(self.row_data[index.row()][col])
            elif col == 2:
                return friendly_datetime(self.row_data[index.row()][col])
        elif role == self.SortRole:
            return self.row_data[index.row()][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[index.row()]
        elif role == self.FilterRole:
            return f"{self.row_data[0][col]} {hex(self.row_data[1][col])}"
        elif role == Qt.ToolTipRole:
            return self.data_tooltips[index.row()]
        return None

    def update_table(self):
        cmenu_cache = {}
        touched_users = []

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

                if user.name in cmenu_cache:
                    cmenu_cache[user.name].append(func_addr)
                else:
                    cmenu_cache[user.name] = [func_addr]

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
                most_recent_func = 0
                last_state_change = state.last_push_time

            row = [user.name, most_recent_func, last_state_change]

            self.data_dict[user.name] = row
            touched_users.append(user.name)

        self.context_menu_cache = cmenu_cache
        data_to_send = []
        colors_to_send = []
        idxs_to_update = []
        for i, (k, v) in enumerate(self.data_dict.items()):
            if k in touched_users:
                idxs_to_update.append(i)
            data_to_send.append(v)

            duration = time.time() - v[self.time_col]  # table coloring
            row_color = None
            if 0 <= duration <= self.controller.table_coloring_window:
                opacity = (self.controller.table_coloring_window - duration) / self.controller.table_coloring_window
                row_color = QColor(BinsyncTableModel.ACTIVE_FUNCTION_COLOR[0],
                                   BinsyncTableModel.ACTIVE_FUNCTION_COLOR[1],
                                   BinsyncTableModel.ACTIVE_FUNCTION_COLOR[2],
                                   int(BinsyncTableModel.ACTIVE_FUNCTION_COLOR[3] * opacity))
            colors_to_send.append(row_color)

            self.data_tooltips.append(f"Age: {friendly_datetime(v[self.time_col])}")

        if len(data_to_send) != self.rowCount():
            idxs_to_update = []

        if self.controller.table_coloring_window != self.saved_color_window:
            self.saved_color_window = self.controller.table_coloring_window
            idxs_to_update = range(len(data_to_send))

        self.update_signal.emit(data_to_send, colors_to_send)

        for idx in idxs_to_update:
            self.dataChanged.emit(self.index(0, idx), self.index(self.rowCount() - 1, idx))


class ActivityTableView(BinsyncTableView):
    HEADER = ['User', 'Activity', 'Last Push']

    def __init__(self, controller: BinSyncController, filteredit: BinsyncTableFilterLineEdit=None, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = ActivityTableModel(controller, self.HEADER, filter_cols=[0, 1], time_col=2,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def _get_valid_funcs_for_user(self, username):
        if username in self.model.context_menu_cache:
            for addr in self.model.context_menu_cache[username]:
                yield hex(addr)
        else:
            # only populate with cached items to prevent main thread waiting on atomic actions
            cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=username,
                                                             priority=SchedSpeed.FAST)
            if cache_item is not None:
                user_state = cache_item
            else:
                return

            func_addrs = [addr for addr in user_state.functions]

            func_addrs.sort()
            for func_addr in func_addrs:
                yield hex(func_addr)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_activity_table_context_menu")

        valid_row = True
        selected_row = self.rowAt(event.pos().y())
        idx = self.proxymodel.index(selected_row, 0)
        idx = self.proxymodel.mapToSource(idx)
        if event.pos().y() == -1 and event.pos().x() == -1:
            idx = self.proxymodel.index(0, 0)
            idx = self.proxymodel.mapToSource(idx)
        elif not (0 <= selected_row < len(self.model.row_data)) or not idx.isValid():
            valid_row = False

        col_hide_menu = menu.addMenu("Show Columns")
        handler = lambda ind: lambda: self._col_hide_handler(ind)
        for i, c in enumerate(self.HEADER):
            act = QAction(c, parent=menu)
            act.setCheckable(True)
            act.setChecked(self.column_visibility[i])
            act.triggered.connect(handler(i))
            col_hide_menu.addAction(act)

        if valid_row:
            func_addr = self.model.row_data[idx.row()][1]
            user_name = self.model.row_data[idx.row()][0]

            menu.addSeparator()
            if isinstance(func_addr, int) and func_addr > 0:
                menu.addAction("Sync", lambda: self.controller.fill_function(func_addr, user=user_name))
            menu.addAction("Sync-All", lambda: self.controller.fill_all(user=user_name))

            for_menu = menu.addMenu(f"Sync from {user_name} for...")
            for func_addr_str in self._get_valid_funcs_for_user(user_name):
                action = for_menu.addAction(func_addr_str)
                action.triggered.connect(
                    lambda chk, func=func_addr_str: self.controller.fill_function(func_addr, user=user_name))

        menu.popup(self.mapToGlobal(event.pos()))


class QActivityTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.table = ActivityTableView(self.controller, filteredit=None, stretch_col=1, col_count=3)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self):
        self.table.update_table()

    def reload(self):
        pass
