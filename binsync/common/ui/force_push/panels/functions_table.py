import logging
from datetime import datetime
from typing import Dict

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
    QPushButton,
    QPersistentModelIndex,
    QCheckBox
)
from binsync.common.ui.utils import friendly_datetime
from binsync.data import Function
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


class FunctionTableModel(QAbstractTableModel):
    """Table model that controls backend behavior of the function table"""
    HEADER = [
        'Addr',
        'Remote Name',
        'User',
        'Last Push'
    ]

    # This is *most likely* alright, definitely works on linux, could use a macos/windows pass.
    # Custom defined role for sorting (since we shouldn't sort hex numbers alphabetically)
    SortRole = Qt.UserRole + 1000

    # Color for most recently updated, the alpha value decreases linearly over controller.table_coloring_window
    ACTIVE_FUNCTION_COLOR = (100, 255, 100, 70)

    def __init__(self, controller: BinSyncController, data=None, parent=None, load_from="bs"):
        super().__init__(parent)
        self.controller = controller
        self.row_data = data if data else []
        
        self.load_from = load_from
        if load_from == "bs":
            self.data_bgcolors = []
        else:
            self.checks = {}
            self.HEADER[1] = 'Name'

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
        elif role == FunctionTableModel.SortRole:
            if index.column() == 0:
                return self.row_data[index.row()][0]
            elif index.column() == 1:
                return self.row_data[index.row()][1]
            elif index.column() == 2:
                return self.row_data[index.row()][2]
            elif index.column() == 3:
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
            self.row_data.insert(position + row, [0, "LOADING", "USER", datetime.now()])
            if self.load_from == "bs": self.data_bgcolors.insert(position + row, [QColor(0, 0, 0, 0)])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.row_data) and 0 <= position + rows < len(self.row_data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)

            del self.row_data[position:position + rows]
            if self.load_from == "bs": del self.colordata[position:position + rows]

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
            if 0 == index.column() and role == Qt.CheckStateRole:
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

    def entry_exists(self, addr):
        """ Quick way to determine if an entry already exists via addr """
        return addr in [i[0] for i in self.row_data]

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
                alpha = self.ACTIVE_FUNCTION_COLOR[3]
                recency_percent = (self.controller.table_coloring_window - duration) / self.controller.table_coloring_window
                self.data_bgcolors[i] = QColor(self.ACTIVE_FUNCTION_COLOR[0], self.ACTIVE_FUNCTION_COLOR[1],
                                               self.ACTIVE_FUNCTION_COLOR[2], int(alpha * recency_percent))
            else:
                self.data_bgcolors[i] = None  # None will just cause no color changes from the default

    def update_table_from_bs(self):
        # for each user, iterate over all of their functions
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_funcs: Dict[int, Function] = state.functions

            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change

                # don't add functions that were never changed by the user
                if not sync_func.last_change:
                    continue

                tab_idx = 0
                exists = self.entry_exists(func_addr)
                if exists:
                    # compare this users change time to the store change time
                    tab_idx = [i[0] for i in self.row_data].index(func_addr)
                    if not func_change_time or func_change_time < self.row_data[tab_idx][3]:
                        continue
                # insert a new row if necessary
                if not exists:
                    self.insertRows(0)
                # get its index to use and set the data for all 4 columns
                row_data = [func_addr, sync_func.name if sync_func.name else "", user.name, func_change_time]
                for i in range(4):
                    idx = self.index(tab_idx, i, QModelIndex())
                    self.setData(idx, row_data[i], role=Qt.EditRole)

    def update_table_from_decompiler(self):
        for address, function in self.controller.functions().items():
            if self.entry_exists(address):
                func_index = list(map(lambda x: x[0], self.row_data)).index(address)
                func_name_idx = self.index(func_index, 1, QModelIndex())
                self.setData(func_name_idx, function.name, role=Qt.EditRole)
                continue
 
            self.insertRows(0)
            row_data = [address, function.name, "", -1]
            for i in range(4):
                idx = self.index(0, i, QModelIndex())
                self.setData(idx, row_data[i], role=Qt.EditRole)
        self.update_checks()

    def update_table(self):
        """ Updates the table using the controller's information """
        self.update_table_from_bs()
        if self.load_from == "decompiler": self.update_table_from_decompiler()
        else: self.update_table_colors()

class FunctionTableFilterLineEdit(QLineEdit):
    """ Basic class for the filter line edit, clears itself whenever focus is lost. """
    def __init__(self, parent=None):
        super(FunctionTableFilterLineEdit, self).__init__(parent=parent)
        self.user_unfocused = False

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.user_unfocused:
            self.user_unfocused = False
            self.clear()

        if event.key() == Qt.Key_Escape:
            self.clear()
            return
        super(FunctionTableFilterLineEdit, self).keyPressEvent(event)

    def focusOutEvent(self, event: QFocusEvent) -> None:
        if event.reason() == Qt.MouseFocusReason:
            self.user_unfocused = True
        super(FunctionTableFilterLineEdit, self).focusOutEvent(event)


class FunctionTableView(QTableView):
    """ Table view for the data, this is the front end "container" for our model. """

    def __init__(self, controller: BinSyncController, filteredit: FunctionTableFilterLineEdit, parent=None, load_from="bs"):
        super().__init__(parent=parent)
        self.load_from = load_from
        self.controller = controller

        self.filteredit = filteredit
        self.filteredit.textChanged.connect(self.handle_filteredit_change)

        # Create a SortFilterProxyModel to allow for sorting/filtering
        self.proxymodel = QSortFilterProxyModel()
        # Set the sort role/column to filter by
        self.proxymodel.setSortRole(FunctionTableModel.SortRole)
        self.proxymodel.setFilterRole(Qt.DisplayRole)
        self.proxymodel.setFilterKeyColumn(-1)

        # Connect our model to the proxy model
        self.model = FunctionTableModel(controller, load_from=self.load_from)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)
        self.column_visibility = []

        if self.load_from == "bs":
            self.doubleClicked.connect(self._doubleclick_handler)

        self._init_settings()

    def _doubleclick_handler(self):
        """ Handler for double clicking on a row, jumps to the respective function. """
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        row = self.model.row_data[tls_row_idx.row()]
        self.controller.goto_address(row[0])

    def _get_valid_users_for_func(self, func_addr):
        """ Helper function for getting users that have changes in a given function """
        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            user_func = user_state.get_function(func_addr)

            # function must be changed by this user
            if not user_func or not user_func.last_change:
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
        if self.load_from == "bs":
            menu = QMenu(self)
            menu.setObjectName("binsync_function_table_context_menu")
            valid_row = True
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
                func_addr = self.model.row_data[idx.row()][0]
                user_name = self.model.row_data[idx.row()][2]

                menu.addSeparator()
                menu.addAction("Sync", lambda: self.controller.fill_function(func_addr, user=user_name))
                from_menu = menu.addMenu("Sync from...")

                for username in self._get_valid_users_for_func(func_addr):
                    action = from_menu.addAction(username)
                    action.triggered.connect(
                        lambda chck, name=username: self.controller.fill_function(func_addr, user=name))

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

    def handle_filteredit_change(self, text):
        """ Handle text changes in the filter box, filters the table by the arg. """
        self.proxymodel.setFilterFixedString(text)
        if self.load_from == "decompiler": self.select_all.setChecked(False)

    def push(self):
        functions = self.controller.functions()
        for qpmi, state in self.model.checks.items():
            if state:
                func_addr = int(self.model.data(qpmi), 16)
                self.controller.force_push_function(func_addr) 

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

class QFunctionTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """
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
        self.filteredit = FunctionTableFilterLineEdit(parent=self)
        self.table = FunctionTableView(self.controller, self.filteredit, parent=self, load_from=self.load_from)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        if self.load_from=="bs":
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
