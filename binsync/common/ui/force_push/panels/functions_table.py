import logging
from datetime import datetime
from typing import Dict

from binsync.common.controller import BinSyncController
from PyQt5.QtCore import QPersistentModelIndex
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
    QHBoxLayout,
    QPushButton
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
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

    def __init__(self, controller: BinSyncController, data=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        if data is None:
            self.data = []  # holds sublists of form: (addr, name, user_name, push_time)
        else:
            self.data = data
        self.checks = {}
        self.all_functions = self.controller.get_all_functions()

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return 4

    def checkState(self, index):
        if index in self.checks.keys():
            return self.checks[index]
        else:
            return Qt.Unchecked

    def data(self, index, role=Qt.DisplayRole):
        """ Returns information about the data at a specified index based
            on the role supplied. """
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            if index.column() == 0:
                return f"{self.data[index.row()][0]:#6x}"
            elif index.column() == 1:
                return self.data[index.row()][1]
            elif index.column() == 2:
                return self.data[index.row()][2]
            elif index.column() == 3:
                return friendly_datetime(self.data[index.row()][3])
        elif role == FunctionTableModel.SortRole:
            if index.column() == 0:
                return self.data[index.row()][0]
            elif index.column() == 1:
                return self.data[index.row()][1]
            elif index.column() == 2:
                return self.data[index.row()][2]
            elif index.column() == 3:
                return self.data[index.row()][3]
        elif role == Qt.CheckStateRole and index.column() == 0:
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
            self.data.insert(position + row, [0, "LOADING", "USER", datetime.now()])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        self.beginRemoveRows(QModelIndex(), position, position + rows - 1)

        del self.data[position:position + rows]
        del self.colordata[position:position + rows]

        self.endRemoveRows()
        return True

    def setData(self, index, value, role=Qt.EditRole):
        """ Adjust the data (set it to <value>) depending on the given
            index and role.
        """
        if role != Qt.EditRole and role != Qt.CheckStateRole:
            return False

        if index.isValid() and 0 <= index.row() < len(self.data):
            address = self.data[index.row()]
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
        fl = Qt.ItemFlags(QAbstractTableModel.flags(self, index))
        if index.column()==0: fl = Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled #################################################################
        return fl

    def entry_exists(self, addr):
        """ Quick way to determine if an entry already exists via addr """
        return addr in [i[0] for i in self.data]

    def update_checks(self):
        for i in range(self.rowCount()):
            idx = self.index(i, 0, QModelIndex())
            self.checks[QPersistentModelIndex(idx)] = self.checks.get(QPersistentModelIndex(idx), 0)

    def update_table(self):
        """ Updates the table using the controller's information """
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
                    tab_idx = [i[0] for i in self.data].index(func_addr)
                    if not func_change_time or func_change_time < self.data[tab_idx][3]:
                        continue
                # insert a new row if necessary
                if not exists:
                    self.insertRows(0)
                # get its index to use and set the data for all 4 columns
                row_data = [func_addr, sync_func.name if sync_func.name else "", user.name, func_change_time]
                for i in range(4):
                    idx = self.index(tab_idx, i, QModelIndex())
                    self.setData(idx, row_data[i], role=Qt.EditRole)

        #Then obtain all functions that have not been modified
        for function, ida_name in self.all_functions.items():
            if self.entry_exists(function): continue
            self.insertRows(0)
            row_data = [function, ida_name, "", -1]
            for i in range(4):
                idx = self.index(0, i, QModelIndex())
                self.setData(idx, row_data[i], role=Qt.EditRole)
        self.update_checks()

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
    def __init__(self, controller: BinSyncController, filteredit: FunctionTableFilterLineEdit, parent=None):
        super().__init__(parent=parent)

        self.controller = controller

        self.filteredit = filteredit
        self.filteredit.textChanged.connect(self.handle_filteredit_change)

        # Create a SortFilterProxyModel to allow for sorting/filtering
        self.proxymodel = QSortFilterProxyModel()
        # Set the sort role/column to filter by
        self.proxymodel.setSortRole(FunctionTableModel.SortRole)
        self.proxymodel.setFilterKeyColumn(1)

        # Connect our model to the proxy model
        self.model = FunctionTableModel(controller)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        self._init_settings()

    def _get_valid_users_for_func(self, func_addr):
        """ Helper function for getting users that have changes in a given function """
        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            user_func = user_state.get_function(func_addr)

            # function must be changed by this user
            if not user_func or not user_func.last_change:
                continue

            yield user.name

    def update_table(self):
        """ Update the model of the table with new data from the controller """
        self.model.update_table()

    def reload(self):
        pass

    def _init_settings(self):
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.Stretch)
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

    def handle_filteredit_change(self, text):
        """ Handle text changes in the filter box, filters the table by the arg. """
        self.proxymodel.setFilterFixedString(text)

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

    def push(self):
        raise NotImplementedError

class QFunctionTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """
    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def button_bar(self):
        button1 = QPushButton("select all")
        button1.clicked.connect(self.table.check_all)

        button2 = QPushButton("deselect all")
        button2.clicked.connect(self.table.uncheck_all)

        topbar = QHBoxLayout()
        topbar.addWidget(button1)
        topbar.addWidget(button2)
        return topbar

    def _init_widgets(self):
        self.filteredit = FunctionTableFilterLineEdit(parent=self)
        self.table = FunctionTableView(self.controller, self.filteredit, parent=self)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        layout.addLayout(self.button_bar())
        
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
