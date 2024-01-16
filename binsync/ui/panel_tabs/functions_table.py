import datetime
import logging
import time
from typing import Dict
from collections import defaultdict

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


class FunctionTableModel(BinsyncTableModel):
    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.context_menu_cache = {}

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0:
                return hex(self.row_data[row][col])
            elif col == 1 or col == 2:
                return self.row_data[row][col]
            elif col == 3:
                return friendly_datetime(self.row_data[row][col])
        elif role == self.SortRole:
            if col == self.time_col and isinstance(self.row_data[row][col], datetime.datetime):
                return time.mktime(self.row_data[row][col].timetuple())
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return f"{hex(self.row_data[row][0])} {self.row_data[row][1]} {self.row_data[row][2]}"
        elif role == Qt.ToolTipRole:
            #return self.data_tooltips[index.row()]
            pass
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        # grab all the new info from user states
        for state in states:
            user_funcs: Dict[int, Function] = state.functions
            user_name = state.user
            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change
                # don't add functions that were never changed by the user
                if not func_change_time:
                    continue

                cmenu_cache[func_addr].append(user_name)

                # skip updating existent, older, functions
                if func_addr in self.data_dict and \
                        (not func_change_time or func_change_time <= self.data_dict[func_addr][self.time_col]):
                    continue

                self.data_dict[func_addr] = [
                    func_addr, sync_func.name if sync_func.name else "", user_name, func_change_time
                ]
                updated_row_keys.add(func_addr)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()

class FunctionTableView(BinsyncTableView):
    HEADER = ['Addr', 'Remote Name', 'User', 'Last Push']

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = FunctionTableModel(controller, self.HEADER, filter_cols=[0, 1], time_col=3, addr_col=0,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def _get_valid_users_for_func(self, func_addr):
        """ Helper function for getting users that have changes in a given function """
        if func_addr in self.model.context_menu_cache:
            for username in self.model.context_menu_cache[func_addr]:
                yield username
        else:
            for user in self.controller.client.check_cache_(self.controller.client.users,
                                                            priority=SchedSpeed.FAST, no_cache=False):
                # only populate with cached items to prevent main thread waiting on atomic actions
                cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=user.name,
                                                                 priority=SchedSpeed.FAST)
                if cache_item is not None:
                    user_state = cache_item
                else:
                    continue

                user_func = user_state.get_function(func_addr)

                # function must be changed by this user
                if not user_func or not user_func.last_change:
                    continue

                yield user.name

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_function_table_context_menu")
        valid_row = True
        selected_row = self.rowAt(event.pos().y())
        idx = self.proxymodel.index(selected_row, 0)
        idx = self.proxymodel.mapToSource(idx)
        # support for automated tests
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
            func_addr = self.model.row_data[idx.row()][0]
            user_name = self.model.row_data[idx.row()][2]

            menu.addSeparator()
            if isinstance(func_addr, int) and func_addr > 0:
                menu.addAction("Sync", lambda: self.controller.fill_artifact(func_addr, artifact_type=Function, user=user_name))
            from_menu = menu.addMenu("Sync from...")
            users = self._get_valid_users_for_func(func_addr)
            for username in users:
                action = from_menu.addAction(username)
                action.triggered.connect(
                    lambda checked=False, name=username: self.controller.fill_artifact(func_addr, artifact_type=Function, user=name))
        menu.popup(self.mapToGlobal(event.pos()))


class QFunctionTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = FunctionTableView(self.controller, self.filteredit, stretch_col=1, col_count=4)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self, states):
        self.table.update_table(states)

    def reload(self):
        pass
