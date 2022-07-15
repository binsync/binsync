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
    QVBoxLayout,
    QPersistentModelIndex,
    QCheckBox,
    QPushButton
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

    # Color for most recently updated, the alpha value decreases linearly over controller.table_coloring_window
    ACTIVE_GLOBAL_COLOR = (100, 255, 100, 70)

    def __init__(self, controller: BinSyncController, data=None, parent=None, load_from="bs"):
        super().__init__(parent)
        self.load_from = load_from
        self.controller = controller
        # holds sublists of form: (type, remote name, user, last push)
        self.row_data = data if data else []
        if self.load_from == "bs":
            self.data_bgcolors = []
        else: 
            self.checks = {}

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.row_data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return 4

    def checkState(self, index):
        return self.checks.get(index, Qt.Unchecked)

    def data(self, index, role=Qt.DisplayRole):
        """ Returns information about the data at a specified index based
            on the role supplied. """
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            if index.column() == 0:
                if isinstance(self.row_data[index.row()][0], int):
                    return f"{self.row_data[index.row()][0]:#x}"
                else:
                    return self.row_data[index.row()][0]
            elif index.column() == 1:
                return self.row_data[index.row()][1]
            elif index.column() == 2:
                return self.row_data[index.row()][2]
            elif index.column() == 3:
                return friendly_datetime(self.row_data[index.row()][3])
        elif role == GlobalTableModel.SortRole:
            if index.column() == 0:
                return self.row_data[index.row()][0]
            elif index.column() == 1:
                return self.row_data[index.row()][1]
            elif index.column() == 2:
                return self.row_data[index.row()][2]
            elif index.column() == 3:  # dont filter based on time
                return None
        elif self.load_from == "bs" and role == Qt.BackgroundRole:
            if len(self.row_data) != len(self.data_bgcolors) or not (0 <= index.row() < len(self.data_bgcolors)):
                return None
            return self.data_bgcolors[index.row()]
        elif self.load_from == "decompiler" and role == Qt.CheckStateRole and index.column() == 0:
            return self.checkState(QPersistentModelIndex(index))
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
            self.row_data.insert(position + row, [None, "LOADING", "USER", datetime.now()])
            if self.load_from == "bs": self.data_bgcolors.insert(position + row, [QColor(0, 0, 0, 0)])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.row_data) and 0 <= position + rows < len(self.row_data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)
            del self.row_data[position:position + rows]
            if self.load_from=="bs": del self.data_bgcolors[position:position + rows]
            self.endRemoveRows()

            return True
        return False

    def setData(self, index, value, role=Qt.EditRole):
        """ Adjust the data (set it to <value>) depending on the given
            index and role.
        """
        if role != Qt.EditRole and role != Qt.CheckStateRole:
            return False

        if index.isValid() and 0 <= index.row() < len(self.row_data):
            address = self.row_data[index.row()]
            if 0==index.column() and role == Qt.CheckStateRole:
                self.checks[QPersistentModelIndex(index)] = value
            elif 0 <= index.column() < len(address):
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
        if self.load_from == "decompiler" and index.column()==0: fl = Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled
        else: fl = Qt.ItemFlags(QAbstractTableModel.flags(self, index))
        return fl

    def entry_exists(self, name):
        """ Quick way to determine if an entry already exists via artifact name """
        return name in [i[1] for i in self.row_data]

    def update_checks(self):
        for i in range(self.rowCount()):
            idx = self.index(i, 0, QModelIndex())
            self.checks[QPersistentModelIndex(idx)] = self.checks.get(QPersistentModelIndex(idx), 0)

    def update_table_colors(self):
        # update table coloring, this might need to be checked for robustness
        now = datetime.now()
        for i in range(len(self.row_data)):
            t_upd = self.row_data[i][3]
            if isinstance(t_upd, int):
                if t_upd == -1:
                    self.data_bgcolors[i] = None
                t_upd = datetime.fromtimestamp(t_upd)

            duration = (now - t_upd).total_seconds()

            if 0 <= duration <= self.controller.table_coloring_window:
                alpha = self.ACTIVE_GLOBAL_COLOR[3]
                recency_percent = (self.controller.table_coloring_window - duration) / self.controller.table_coloring_window
                self.data_bgcolors[i] = QColor(self.ACTIVE_GLOBAL_COLOR[0], self.ACTIVE_GLOBAL_COLOR[1],
                                               self.ACTIVE_GLOBAL_COLOR[2], int(alpha * recency_percent))
            else:
                self.data_bgcolors[i] = None  # None will just cause no color changes from the default


    def update_table_from_bs(self):
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
                tab_idx = [i[1] for i in self.row_data].index(row[1])
            else:
                self.insertRows(0)
            for i in range(4):
                idx = self.index(tab_idx, i, QModelIndex())
                self.setData(idx, row[i], role=Qt.EditRole)

    def update_table_from_decompiler(self):
        decompiler_structs = self.controller.structs()
        decompiler_gvars = self.controller.global_vars()
        all_artifacts = [(decompiler_structs, "Struct"), (decompiler_gvars, "Variable")]
        
        for type_artifacts, type in all_artifacts:
            for _, artifact in type_artifacts.items():                      
                row = [type, artifact.name, "", -1]
                tab_idx = 0
                if self.entry_exists(row[1]):
                    tab_idx = [i[1] for i in self.row_data].index(row[1])
                else:
                    self.insertRows(0)
                for i in range(4):
                    idx = self.index(tab_idx, i, QModelIndex())
                    self.setData(idx, row[i], role=Qt.EditRole)
        self.update_checks()

    def update_table(self):
        if self.load_from=="decompiler":self.update_table_from_decompiler()
        else:
            self.update_table_from_bs() 
            self.update_table_colors()

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

    def __init__(self, controller: BinSyncController, filteredit: GlobalTableFilterLineEdit, parent=None, load_from="bs"):
        super().__init__(parent=parent)
        self.load_from = load_from
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
        self.model = GlobalTableModel(controller, load_from=self.load_from)
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
        if self.load_from=="bs":
            menu = QMenu(self)
            menu.setObjectName("binsync_global_table_context_menu")

            valid_row = True
            selected_row = self.rowAt(event.pos().y())
            selected_row = self.rowAt(event.pos().y())
            idx = self.proxymodel.index(selected_row, 0)
            idx = self.proxymodel.mapToSource(idx)
            if event.pos().y() == -1 and event.pos().x() == -1:
                selected_row = 0
                idx = self.proxymodel.index(0, 0)
                idx = self.proxymodel.mapToSource(idx)
            elif not (0 <= selected_row < len(self.model.row_data)) or not idx.isValid():
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
                global_type = self.model.row_data[idx.row()][0]
                global_name = self.model.row_data[idx.row()][1]
                user_name = self.model.row_data[idx.row()][2]
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
        else: pass
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
        if self.load_from == "bs":
            self.setSelectionMode(QAbstractItemView.SingleSelection)
            self.setSelectionBehavior(QAbstractItemView.SelectRows)
        else: 
            self.setSelectionMode(QAbstractItemView.NoSelection)
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
        if self.load_from == "decompiler": self.select_all.setChecked(False)

    def push(self):
        decompiler_structs = self.controller.structs()
        decompiler_gvars = self.controller.global_vars()
        for qpmi, state in self.model.checks.items():
            if state:
                type = self.model.data(qpmi)
                name_qpmi = qpmi.sibling(qpmi.row(), 1)
                name = self.model.data(name_qpmi)
            else: continue
            
            if type=="Struct":
                self.controller.force_push_global_artifact(name)
            elif type=="Variable":
                for addr, gvar in decompiler_gvars.items():
                    if gvar.name == name: 
                        self.controller.force_push_global_artifact(addr)

    def connect_select_all(self, checkbox):
        self.select_all = checkbox

    def check_all(self):
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            qpmi = QPersistentModelIndex(mappedIndex)
            self.model.checks[qpmi] = 2
        self.update_table()

    def uncheck_all(self):
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            qpmi = QPersistentModelIndex(mappedIndex)
            self.model.checks[qpmi] = 0
        self.update_table()


class QGlobalsTable(QWidget):
    """ Wrapper widget to contain the globals table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BinSyncController, parent=None, load_from="bs"):
        super().__init__(parent)
        self.load_from = load_from
        self.controller = controller
        self._init_widgets()

    def toggle_select_all(self):
        if self.checkbox.isChecked():
            self.table.check_all()
        else:
            self.table.uncheck_all()

    def _init_widgets(self):
        self.filteredit = GlobalTableFilterLineEdit(parent=self)
        self.table = GlobalTableView(self.controller, self.filteredit, parent=self, load_from=self.load_from)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        if self.load_from == "bs":
            layout.addWidget(self.table)
            layout.addWidget(self.filteredit)
        else:        
            self.checkbox = QCheckBox("select all")
            self.checkbox.clicked.connect(self.toggle_select_all)
            self.table.connect_select_all(self.checkbox)
            layout.addWidget(self.checkbox)
            layout.addWidget(self.table)
            layout.addWidget(self.filteredit)
            push_button = QPushButton("PUSH")
            push_button.clicked.connect(self.table.push)
            layout.addWidget(push_button)

        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self):
        self.table.update_table()

    def reload(self):
        pass
