import datetime
import logging
from collections import defaultdict
from typing import Dict
import time

from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from libbs.ui.qt_objects import (
    QMenu,
    QAction,
    QWidget,
    QVBoxLayout,
    Qt
)
from binsync.ui.utils import friendly_datetime
from binsync.core.scheduler import SchedSpeed
from libbs.artifacts import Function

l = logging.getLogger(__name__)


class ActivityTableModel(BinsyncTableModel):
    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.saved_color_window = self.controller.table_coloring_window
        self.context_menu_cache = {}

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0:
                return self.row_data[row][col]
            elif col == 1:
                data = self.row_data[row][col]
                return hex(self.row_data[row][col]) if data != -1 else ""
            elif col == 2:
                return friendly_datetime(self.row_data[row][col])
        elif role == self.SortRole:
            if col == self.time_col and isinstance(self.row_data[row][col], datetime.datetime):
                return time.mktime(self.row_data[row][col].timetuple())
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return f"{self.row_data[row][0]} {hex(self.row_data[row][1])}"
        elif role == Qt.ToolTipRole:
            #return self.data_tooltips[row]
            pass
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        for state in states:
            latest_func = None
            user_funcs: Dict[int, Function] = state.functions
            user_name = state.user

            for func_addr, sync_func in user_funcs.items():
                # don't add functions that were never changed by the user
                if not sync_func.last_change:
                    continue

                cmenu_cache[user_name].append(func_addr)

                if latest_func is None:
                    latest_func = sync_func
                    continue

                if latest_func is not None and sync_func.last_change <= latest_func.last_change:
                    continue

                latest_func = sync_func

            if latest_func is not None:
                most_recent_func = latest_func.addr
                last_state_change = latest_func.last_change
            else:
                most_recent_func = -1
                last_state_change = state.last_push_time

            self.data_dict[user_name] = [user_name, most_recent_func, last_state_change]
            updated_row_keys.add(user_name)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()

class ActivityTableView(BinsyncTableView):
    HEADER = ['User', 'Activity', 'Last Push']

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit=None, stretch_col=None,
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
                menu.addAction("Sync", lambda: self.controller.fill_artifact(func_addr, artifact_type=Function, user=user_name))
            menu.addAction("Sync-All", lambda: self.controller.sync_all(user=user_name))

            for_menu = menu.addMenu(f"Sync from {user_name} for...")
            for func_addr_str in self._get_valid_funcs_for_user(user_name):
                action = for_menu.addAction(func_addr_str)
                action.triggered.connect(
                    lambda chk, func=func_addr_str: self.controller.fill_artifact(func_addr, artifact_type=Function, user=user_name))

        menu.popup(self.mapToGlobal(event.pos()))


class QActivityTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BSController, parent=None):
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

    def update_table(self, states):
        self.table.update_table(states)

    def reload(self):
        pass
