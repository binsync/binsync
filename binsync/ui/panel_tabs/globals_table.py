import logging
import datetime
from collections import defaultdict
import time

from libbs.artifacts import GlobalVariable, Struct, Enum, Typedef

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

l = logging.getLogger(__name__)


class GlobalsTableModel(BinsyncTableModel):
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
            if col == GlobalsTableView.COL_TYPE:
                return val[0]  # First letter of the type (T, E, S or V)
            elif col == GlobalsTableView.COL_ADDR:
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
            hexaddr = hex(addr) if addr is not None else ""
            return " ".join((self.row_data[row][GlobalsTableView.COL_TYPE][0],
                             hexaddr,
                             self.row_data[row][GlobalsTableView.COL_NAME],
                             self.row_data[row][GlobalsTableView.COL_USER]))
        elif role == Qt.ToolTipRole:
            # return self.data_tooltips[index.row()]
            pass
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        for state in states:
            user_structs = state.structs
            user_gvars = state.global_vars
            user_enums = state.enums
            user_name = state.user
            user_typedefs = state.typedefs

            all_artifacts = ((user_enums, "Enum"), (user_structs, "Struct"), (user_gvars, "Variable"), (user_typedefs, "Typedef"))
            for user_artifacts, global_type in all_artifacts:
                for _, artifact in user_artifacts.items():
                    change_time = artifact.last_change

                    if not change_time:
                        continue

                    artifact_addr = None
                    if global_type in ("Enum", "Struct", "Typedef"):
                        artifact_key = artifact.name + f"({global_type})"
                    elif global_type in ("Variable",):
                        artifact_key = artifact.addr
                        artifact_addr = artifact.addr
                    else:
                        l.critical("Attempted to parse an unparsable global type!")
                        return

                    cmenu_cache[artifact_key].append((user_name, global_type[0]))

                    # skip updating existent, older, artifacts
                    if artifact_key in self.data_dict and \
                            (not change_time or change_time <= self.data_dict[artifact_key][self.time_col]):
                        continue

                    self.data_dict[artifact_key] = [global_type[0], artifact_addr, artifact.name, user_name, change_time]
                    updated_row_keys.add(artifact_key)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()


class GlobalsTableView(BinsyncTableView):
    HEADER = ['T', 'Addr', 'Name', 'User', 'Last Push']
    COL_TYPE = 0
    COL_ADDR = 1
    COL_NAME = 2
    COL_USER = 3
    COL_DATE = 4
    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = GlobalsTableModel(controller, self.HEADER, filter_cols=[self.COL_TYPE, self.COL_ADDR,
                                                                             self.COL_NAME, self.COL_USER],
                                       time_col=self.COL_DATE, parent=parent)
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
            elif global_type == "T":
                global_getter = "get_typedef"
            else:
                l.warning("Failed to get a valid type for global type '%s'", global_type)
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
            global_type = self.model.row_data[idx.row()][self.COL_TYPE]
            global_name = self.model.row_data[idx.row()][self.COL_NAME]
            global_addr = self.model.row_data[idx.row()][self.COL_ADDR]
            user_name = self.model.row_data[idx.row()][self.COL_USER]
            if any(x is None for x in [global_type, global_name, user_name]):
                menu.popup(self.mapToGlobal(event.pos()))
                return

            if global_type == "S":
                filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(global_name, artifact_type=Struct, user=username)
            elif global_type == "V":
                global_name = global_addr
                filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(global_name, artifact_type=GlobalVariable, user=username)
            elif global_type == "E":
                filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(global_name, artifact_type=Enum, user=username)
            elif global_type == "T":
                filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(global_name, artifact_type=Typedef, user=username)
            else:
                l.warning("Invalid global table sync option: %s", global_type)
                return

            menu.addSeparator()
            action = menu.addAction("Sync")
            action.triggered.connect(filler_func(user_name))
            from_menu = menu.addMenu("Sync from...")
            for username in self._get_valid_users_for_global(global_name, global_type):
                action = from_menu.addAction(username)
                action.triggered.connect(filler_func(username))

        menu.popup(self.mapToGlobal(event.pos()))

    def _doubleclick_handler(self):
        """ Handler for double clicking on a row, jumps to the respective global variable or type. """
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        row = self.model.row_data[tls_row_idx.row()]
        global_type = row[self.COL_TYPE]
        if global_type == 'V':
            self.controller.deci.gui_goto(row[self.COL_ADDR])
        else:
            self.controller.deci.gui_show_type(row[self.COL_NAME])

class QGlobalsTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        col_count = len([col for col in GlobalsTableView.__dict__ if col.startswith("COL_")])
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = GlobalsTableView(self.controller, self.filteredit, stretch_col=GlobalsTableView.COL_NAME,
                                      col_count=col_count)
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
