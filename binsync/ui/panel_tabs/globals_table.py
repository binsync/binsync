import logging
import datetime
from collections import defaultdict
import time

from declib.artifacts import GlobalVariable

from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from declib.ui.qt_objects import (
    QMenu,
    QAction,
    QWidget,
    QVBoxLayout,
    Qt,
)
from binsync.ui.utils import friendly_datetime
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


class GlobalsTableModel(BinsyncTableModel):
    """Activity model for global variables only (addr-keyed)."""

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
        val = self.row_data[row][col]
        if role == Qt.DisplayRole:
            if col == GlobalsTableView.COL_ADDR:
                return hex(val) if val is not None else ""
            elif col in (GlobalsTableView.COL_NAME, GlobalsTableView.COL_USER):
                return val
            elif col == GlobalsTableView.COL_DATE:
                return friendly_datetime(val)
        elif role == self.SortRole:
            if col == self.time_col and isinstance(val, datetime.datetime):
                return time.mktime(val.timetuple())
            return val
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            addr = self.row_data[row][GlobalsTableView.COL_ADDR]
            return " ".join((
                hex(addr) if addr is not None else "",
                self.row_data[row][GlobalsTableView.COL_NAME] or "",
                self.row_data[row][GlobalsTableView.COL_USER] or "",
            ))
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        for state in states:
            user_name = state.user
            for _, gvar in state.global_vars.items():
                change_time = gvar.last_change
                if not change_time:
                    continue

                key = gvar.addr
                cmenu_cache[key].append(user_name)

                # skip updating existing, older artifacts
                if key in self.data_dict and \
                        (not change_time or change_time <= self.data_dict[key][self.time_col]):
                    continue

                self.data_dict[key] = [gvar.addr, gvar.name, user_name, change_time]
                updated_row_keys.add(key)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()


class GlobalsTableView(BinsyncTableView):
    HEADER = ['Addr', 'Name', 'User', 'Last Push']
    COL_ADDR = 0
    COL_NAME = 1
    COL_USER = 2
    COL_DATE = 3

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = GlobalsTableModel(
            controller, self.HEADER,
            filter_cols=[self.COL_ADDR, self.COL_NAME, self.COL_USER],
            time_col=self.COL_DATE, addr_col=self.COL_ADDR, parent=parent,
        )
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)
        self._init_settings()

    def _get_valid_users_for_gvar(self, gvar_addr):
        if gvar_addr in self.model.context_menu_cache:
            for user_name in self.model.context_menu_cache[gvar_addr]:
                yield user_name
            return

        for user in self.controller.client.check_cache_(self.controller.client.users,
                                                        priority=SchedSpeed.FAST, fetch_cache=True):
            cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=user.name,
                                                              priority=SchedSpeed.FAST)
            if cache_item is None:
                continue
            user_global = cache_item.get_global_var(gvar_addr)
            if not user_global or not user_global.last_change:
                continue
            yield user.name

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_global_table_context_menu")

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
            gvar_addr = self.model.row_data[idx.row()][self.COL_ADDR]
            user_name = self.model.row_data[idx.row()][self.COL_USER]
            if gvar_addr is None or user_name is None:
                menu.popup(self.mapToGlobal(event.pos()))
                return

            filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(
                gvar_addr, artifact_type=GlobalVariable, user=username
            )

            menu.addSeparator()
            action = menu.addAction("Sync")
            action.triggered.connect(filler_func(user_name))
            from_menu = menu.addMenu("Sync from...")
            for username in self._get_valid_users_for_gvar(gvar_addr):
                action = from_menu.addAction(username)
                action.triggered.connect(filler_func(username))

        menu.popup(self.mapToGlobal(event.pos()))

    def _doubleclick_handler(self):
        """Jump to the global variable in the decompiler."""
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        addr = self.model.row_data[tls_row_idx.row()][self.COL_ADDR]
        if addr is not None:
            self.controller.deci.gui_goto(addr)


class QGlobalsTable(QWidget):
    """Control panel tab listing per-user activity on global variables."""

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        col_count = len([col for col in GlobalsTableView.__dict__ if col.startswith("COL_")])
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = GlobalsTableView(self.controller, self.filteredit,
                                       stretch_col=GlobalsTableView.COL_NAME, col_count=col_count)
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
