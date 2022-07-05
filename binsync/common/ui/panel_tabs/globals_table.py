import logging
import re
from datetime import datetime

from binsync.common.controller import BinSyncController
from binsync.common.ui.qt_objects import (
    QAbstractItemView,
    QAbstractTableModel,
    QHeaderView,
    QMenu,
    Qt,
    QModelIndex,
    QSortFilterProxyModel,
    QColor,
    QFocusEvent,
    QKeyEvent,
    QLineEdit,
    QTableView,
    QFontDatabase,
    QAction,
    QWidget,
    QVBoxLayout
)
from binsync.common.ui.utils import friendly_datetime
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


class GlobalTableModel(QAbstractTableModel):
    """Table model that controls backend behavior of the global table"""
    HEADER = [
        'T',
        'Name',
        'User',
        'Last Push'
    ]

    # This is *most likely* alright, definitely works on linux, could use a macos/windows pass.
    # Custom defined role for sorting (since we shouldn't sort hex numbers alphabetically)
    SortRole = Qt.UserRole + 1000

    # Time window of changes to color, e.g. a 2 hour window will color new updates and fade the color over 2 hours
    COLORING_TIME_WINDOW = 90 * 24 * 60 * 60  # 90 days in seconds

    # Color for most recently updated, the alpha value decreases linearly over COLORING_TIME_WINDOW
    ACTIVE_GLOBAL_COLOR = (100, 255, 100, 70)

    def __init__(self, controller: BinSyncController, data=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        if data is None:
            self.data = []  # holds sublists of form: (addr, name, user_name, push_time)
        else:
            self.data = data

        self.data_bgcolors = []

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return 4

    def data(self, index, role=Qt.DisplayRole):
        """ Returns information about the data at a specified index based
            on the role supplied. """
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            if index.column() == 0:
                if self.data[index.row()][0]:
                    return f"{self.data[index.row()][0][0]}"
            elif index.column() == 1:
                return self.data[index.row()][1]
            elif index.column() == 2:
                return self.data[index.row()][2]
            elif index.column() == 3:
                return friendly_datetime(self.data[index.row()][3])
        elif role == GlobalTableModel.SortRole:
            if index.column() == 0:
                return self.data[index.row()][0]
            elif index.column() == 1:
                return self.data[index.row()][1]
            elif index.column() == 2:
                return self.data[index.row()][2]
            elif index.column() == 3:  # dont filter based on time
                return None
        elif role == Qt.BackgroundRole:
            if len(self.data) != len(self.data_bgcolors) or not (0 <= index.row() < len(self.data_bgcolors)):
                return None
            return self.data_bgcolors[index.row()]

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """ Set the headers to be displayed. """
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            if 0 <= section < len(self.HEADER):
                return self.HEADER[section]

        return None

    def insertRows(self, position, rows=1, index=QModelIndex()):
        """ Insert N (default=1) rows into the model at a desired position. """
        self.beginInsertRows(QModelIndex(), position, position + rows - 1)

        for row in range(rows):
            self.data.insert(position + row, [None, "LOADING", "USER", datetime.now()])
            self.data_bgcolors.insert(position + row, [QColor(0, 0, 0, 0)])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.data) and 0 <= position + rows < len(self.data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)
            del self.data[position:position + rows]
            del self.data_bgcolors[position:position + rows]
            self.endRemoveRows()

            return True
        return False

    def setData(self, index, value, role=Qt.EditRole):
        """ Adjust the data (set it to <value>) depending on the given
            index and role.
        """
        if role != Qt.EditRole:
            return False

        if index.isValid() and 0 <= index.row() < len(self.data):
            address = self.data[index.row()]
            if 0 <= index.column() < len(address):
                address[index.column()] = value
            else:
                return False
            # TODO: Check for compatibility issues with pyqt6 here, function prototype changes between versions
            self.dataChanged.emit(index, index)
            return True

        return False

    def flags(self, index):
        """ Set the item flags at the given index. """
        if not index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

    def entry_exists(self, name):
        """ Quick way to determine if an entry already exists via artifact name """
        return name in [i[1] for i in self.data]

    def update_table(self):
        """ Updates the table using the controller's information """
        known_globals = {}

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

                    if artifact.name in known_globals:
                        # change_time < artifact_stored_change_time
                        if not change_time or change_time < known_globals[artifact.name][3]:
                            continue

                    artifact_name = artifact.name if global_type != "Variable" \
                        else f"{artifact.name} ({hex(artifact.addr)})"

                    known_globals[artifact_name] = (global_type, artifact_name, user.name, change_time)

        for name, row in known_globals.items():
            tab_idx = 0
            if self.entry_exists(row[1]):
                tab_idx = [i[1] for i in self.data].index(row[1])
            else:
                self.insertRows(0)
            for i in range(4):
                idx = self.index(tab_idx, i, QModelIndex())
                self.setData(idx, row[i], role=Qt.EditRole)

        # update table coloring, this might need to be checked for robustness
        now = datetime.now()
        for i in range(len(self.data)):
            t_upd = self.data[i][3]
            if isinstance(t_upd, int):
                if t_upd == -1:
                    self.data_bgcolors[i] = None
                t_upd = datetime.fromtimestamp(t_upd)

            duration = (now - t_upd).total_seconds()

            if 0 <= duration <= self.COLORING_TIME_WINDOW:
                alpha = self.ACTIVE_GLOBAL_COLOR[3]
                recency_percent = (self.COLORING_TIME_WINDOW - duration) / self.COLORING_TIME_WINDOW
                self.data_bgcolors[i] = QColor(self.ACTIVE_GLOBAL_COLOR[0], self.ACTIVE_GLOBAL_COLOR[1],
                                               self.ACTIVE_GLOBAL_COLOR[2], int(alpha * recency_percent))
            else:
                self.data_bgcolors[i] = None  # None will just cause no color changes from the default


class GlobalTableFilterLineEdit(QLineEdit):
    """ Basic class for the filter line edit, clears itself whenever focus is lost. """

    def __init__(self, parent=None):
        super(GlobalTableFilterLineEdit, self).__init__(parent=parent)
        self.user_unfocused = False

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.user_unfocused:
            self.user_unfocused = False
            self.clear()

        if event.key() == Qt.Key_Escape:
            self.clear()
            return
        super(GlobalTableFilterLineEdit, self).keyPressEvent(event)

    def focusOutEvent(self, event: QFocusEvent) -> None:
        if event.reason() == Qt.MouseFocusReason:
            self.user_unfocused = True
        super(GlobalTableFilterLineEdit, self).focusOutEvent(event)


class GlobalTableView(QTableView):
    """ Table view for the data, this is the front end "container" for our model. """

    def __init__(self, controller: BinSyncController, filteredit: GlobalTableFilterLineEdit, parent=None):
        super().__init__(parent=parent)

        self.controller = controller

        self.filteredit = filteredit
        self.filteredit.textChanged.connect(self.handle_filteredit_change)

        # Create a SortFilterProxyModel to allow for sorting/filtering
        self.proxymodel = QSortFilterProxyModel()
        # Set the sort role/column to filter by
        self.proxymodel.setSortRole(GlobalTableModel.SortRole)
        self.proxymodel.setFilterRole(Qt.DisplayRole)
        self.proxymodel.setFilterKeyColumn(-1)

        # Connect our model to the proxy model
        self.model = GlobalTableModel(controller)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        self.column_visibility = []

        self._init_settings()

    def _get_valid_users_for_global(self, global_name, global_type):
        """ Helper function for getting all valid users for a given global """
        if global_type == "Struct":
            global_getter = "get_struct"
        elif global_type == "Variable":
            global_getter = "get_global_var"
        elif global_type == "Enum":
            global_getter = "get_enum"
        else:
            l.warning("Failed to get a valid type for global type")
            return

        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            get_global = getattr(user_state, global_getter)
            user_global = get_global(global_name)

            # function must be changed by this user
            if not user_global or not user_global.last_change:
                continue

            yield user.name

    def _col_hide_handler(self, index):
        """ Helper function to hide/show columns from context menu """
        self.column_visibility[index] = not self.column_visibility[index]
        self.setColumnHidden(index, self.column_visibility[index])
        if self.column_visibility[index]:
            self.showColumn(index)
        else:
            self.hideColumn(index)

    def update_table(self):
        """ Update the model of the table with new data from the controller """
        self.model.update_table()

    def reload(self):
        pass

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_global_table_context_menu")

        valid_row = True
        selected_row = self.rowAt(event.pos().y())
        idx = self.proxymodel.index(selected_row, 0)
        idx = self.proxymodel.mapToSource(idx)
        if not (0 <= selected_row < len(self.model.data)) or not idx.isValid():
            valid_row = False

        col_hide_menu = menu.addMenu("Show Columns")
        handler = lambda ind: lambda: self._col_hide_handler(ind)
        for i, c in enumerate(self.model.HEADER):
            act = QAction(c, parent=menu)
            act.setCheckable(True)
            act.setChecked(self.column_visibility[i])
            act.triggered.connect(handler(i))
            col_hide_menu.addAction(act)

        if valid_row:
            global_type = self.model.data[idx.row()][0]
            global_name = self.model.data[idx.row()][1]
            user_name = self.model.data[idx.row()][2]
            if any(x is None for x in [global_type, global_name, user_name]):
                menu.popup(self.mapToGlobal(event.pos()))
                return

            if global_type == "Struct":
                filler_func = lambda username: lambda chk: self.controller.fill_struct(global_name, user=username)
            elif global_type == "Variable":
                var_addr = int(re.findall(r'0x[a-f,0-9]+', global_name.split(" ")[1])[0], 16)
                global_name = var_addr
                filler_func = lambda username: lambda chk: self.controller.fill_global_var(global_name, user=username)
            elif global_type == "Enum":
                filler_func = lambda username: lambda chk: self.controller.fill_enum(global_name, user=username)
            else:
                l.warning(f"Invalid global table sync option: {global_type}")
                return

            menu.addSeparator()
            menu.addAction("Sync", filler_func(user_name))
            from_menu = menu.addMenu("Sync from...")
            for username in self._get_valid_users_for_global(global_name, global_type):
                action = from_menu.addAction(username)
                action.triggered.connect(filler_func(username))

        menu.popup(self.mapToGlobal(event.pos()))

    def _init_settings(self):
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setSortIndicator(0, Qt.AscendingOrder)
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.column_visibility = [True for _ in range(self.model.columnCount())]

        fixed_width_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        fixed_width_font.setPointSize(11)
        self.setFont(fixed_width_font)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.setWordWrap(False)

        vheader = self.verticalHeader()
        vheader.setDefaultSectionSize(24)
        vheader.hide()

        self.setFocusProxy(self.filteredit)

    # This entire function might be replaceable with a lambda
    def handle_filteredit_change(self, text):
        """ Handle text changes in the filter box, filters the table by the arg. """
        self.proxymodel.setFilterFixedString(text)


class QGlobalsTable(QWidget):
    """ Wrapper widget to contain the globals table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.filteredit = GlobalTableFilterLineEdit(parent=self)
        self.table = GlobalTableView(self.controller, self.filteredit, parent=self)
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
