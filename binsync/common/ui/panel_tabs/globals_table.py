import logging
import time
from typing import Dict
import re
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

class GlobalsTableModel(BinsyncTableModel):
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
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0:
                return self.row_data[row][col][0]
            elif col == 1 or col == 2:
                return self.row_data[row][col]
            elif col == 3:
                return friendly_datetime(self.row_data[row][col])
        elif role == self.SortRole:
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            print(self.row_data)
            print(self.row_data[row][0] + " " + self.row_data[row][1] + " " + self.row_data[row][2])
            return self.row_data[row][0] + " " + self.row_data[row][1] + " " + self.row_data[row][2]
        elif role == Qt.ToolTipRole:
            return self.data_tooltips[index.row()]
        return None

    def update_table(self):
        cmenu_cache = {}
        touched_globals = []
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_structs = state.structs
            user_gvars = state.global_vars
            user_enums = state.enums

            all_artifacts = ((user_enums, "Enum"), (user_structs, "Struct"), (user_gvars, "Variable"))
            for user_artifacts, global_type in all_artifacts:
                for _, artifact in user_artifacts.items():
                    change_time = artifact.last_change

                    if not change_time:
                        continue

                    artifact_name = artifact.name if global_type != "Variable" \
                        else f"{artifact.name} ({hex(artifact.addr)})"

                    if artifact_name in cmenu_cache:
                        cmenu_cache[artifact_name].append((user.name, global_type[0]))
                    else:
                        cmenu_cache[artifact_name] = [(user.name, global_type[0])]

                    if artifact.name in self.data_dict:
                        # change_time < artifact_stored_change_time
                        if not change_time or change_time < self.data_dict[artifact.name][3]:
                            continue

                    self.data_dict[artifact_name] = [global_type[0], artifact_name, user.name, change_time]
                    touched_globals.append(artifact_name)

        self.context_menu_cache = cmenu_cache
        data_to_send = []
        colors_to_send = []
        idxs_to_update = []
        for i, (k, v) in enumerate(self.data_dict.items()):
            if k in touched_globals:
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

        # no changes required, dont bother updating
        if len(idxs_to_update) == 0 and self.controller.table_coloring_window == self.saved_color_window:
            return

        if len(data_to_send) != self.rowCount():
            idxs_to_update = []

        if self.controller.table_coloring_window != self.saved_color_window:
            self.saved_color_window = self.controller.table_coloring_window
            idxs_to_update = range(len(data_to_send))

        self.update_signal.emit(data_to_send, colors_to_send)

        for idx in idxs_to_update:
            self.dataChanged.emit(self.index(0, idx), self.index(self.rowCount() - 1, idx))


class GlobalsTableView(BinsyncTableView):
    HEADER = ['T', 'Name', 'User', 'Last Push']
    def __init__(self, controller: BinSyncController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = GlobalsTableModel(controller, self.HEADER, filter_cols=[0, 1, 2], time_col=3,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def _get_valid_users_for_global(self, global_name, global_type):
        """ Helper function for getting all valid users for a given global """
        if global_name in self.model.context_menu_cache:
            for username, gtype in self.model.context_menu_cache[global_name]:
                if gtype == global_type:
                    yield username
        else:
            if global_type == "S":
                global_getter = "get_struct"
            elif global_type == "V":
                global_getter = "get_global_var"
            elif global_type == "E":
                global_getter = "get_enum"
            else:
                l.warning(f"Failed to get a valid type for global type '{global_type}'")
                return

            for user in self.controller.client.check_cache_(self.controller.client.users,
                                                            priority=SchedSpeed.FAST, no_cache=False):
                # only populate with cached items to prevent main thread waiting on atomic actions
                cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=user.name,
                                                                 priority=SchedSpeed.FAST)
                if cache_item is not None:
                    user_state = cache_item
                else:
                    continue

                get_global = getattr(user_state, global_getter)
                user_global = get_global(global_name)

                # function must be changed by this user
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
            global_type = self.model.row_data[idx.row()][0]
            global_name = self.model.row_data[idx.row()][1]
            user_name = self.model.row_data[idx.row()][2]
            if any(x is None for x in [global_type, global_name, user_name]):
                menu.popup(self.mapToGlobal(event.pos()))
                return

            if global_type == "S":
                filler_func = lambda username: lambda chk=False: self.controller.fill_struct(global_name, user=username)
            elif global_type == "V":
                var_addr = int(re.findall(r'0x[a-f,0-9]+', global_name.split(" ")[1])[0], 16)
                global_name = var_addr
                filler_func = lambda username: lambda chk=False: self.controller.fill_global_var(global_name, user=username)
            elif global_type == "E":
                filler_func = lambda username: lambda chk=False: self.controller.fill_enum(global_name, user=username)
            else:
                l.warning(f"Invalid global table sync option: {global_type}")
                return

            menu.addSeparator()
            action = menu.addAction("Sync")
            action.triggered.connect(filler_func(user_name))
            from_menu = menu.addMenu(f"Sync from...")
            for username in self._get_valid_users_for_global(global_name, global_type):
                action = from_menu.addAction(username)
                action.triggered.connect(filler_func(username))

        menu.popup(self.mapToGlobal(event.pos()))

class QGlobalsTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = GlobalsTableView(self.controller, self.filteredit, stretch_col=1, col_count=4)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self):
        self.table.update_table()

    def reload(self):
        pass
