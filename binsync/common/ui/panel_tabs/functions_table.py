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
    QVBoxLayout
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
from binsync.data import Function
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)

class FunctionTableModel(QAbstractTableModel):
    HEADER = [
        'Addr',
        'Remote Name',
        'User',
        'Last Push'
    ]

    SortRole = Qt.UserRole + 1000
    #COLORING_TIME_WINDOW = 2 * 60 * 60 # 2 hours in seconds
    COLORING_TIME_WINDOW = 90 * 24 * 60 * 60 # 90 days in seconds

    # max color for most recently updated, fades out over COLORING_TIME_WINDOW
    ACTIVE_FUNCTION_COLOR = (100, 255, 100, 70)

    def __init__(self, controller: BinSyncController, data=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        if data is None:
            self.data = []  # holds sublists of form: (addr, name, user_name, push_time)
        else:
            self.data = data

        self.colordata = []

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
        elif role == Qt.BackgroundRole:
            if len(self.data) != len(self.colordata):
                return None
            return self.colordata[index.row()]
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
        """ Insert a row into the model. """
        self.beginInsertRows(QModelIndex(), position, position + rows - 1)

        for row in range(rows):
            self.data.insert(position + row, [0, "LOADING", "USER", datetime.now()])
            self.colordata.insert(position + row, [QColor(0,0,0,0)])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove a row from the model. """
        self.beginRemoveRows(QModelIndex(), position, position + rows - 1)

        del self.data[position:position + rows]
        del self.colordata[position:position + rows]

        self.endRemoveRows()
        return True

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
            # TODO: Check for compatibility issues with pyqt6 here, they add an extra parameter.
            self.dataChanged.emit(index, index)
            return True

        return False

    def flags(self, index):
        """ Set the item flags at the given index. """
        if not index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

    def entry_exists(self, addr):
        """ Quick way to determine if an entry already exists via addr """
        return addr in [i[0] for i in self.data]

    def update_table(self):
        """ Updates the table using the controller's information """
        new_rows = 0
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
                    new_rows += 1
                # get its index to use and set the data for all 4 columns
                row_data = [func_addr, sync_func.name if sync_func.name else "", user.name, func_change_time]
                for i in range(4):
                    idx = self.index(tab_idx, i, QModelIndex())
                    self.setData(idx, row_data[i], role=Qt.EditRole)

        # update table coloring
        now = datetime.now()
        if isinstance(now, int):
            if now == -1:
                self.colordata[i] = None
            t_upd = datetime.fromtimestamp(now)
        for i in range(len(self.data)):
            row = self.data[i]
            t_upd = row[3]
            if isinstance(t_upd, int):
                if t_upd == -1:
                    self.colordata[i] = None
                t_upd = datetime.fromtimestamp(t_upd)
            duration = (now - t_upd).total_seconds()
            if 0 <= duration <= self.COLORING_TIME_WINDOW:
                alpha = self.ACTIVE_FUNCTION_COLOR[3]
                recency_percent = (self.COLORING_TIME_WINDOW-duration) / self.COLORING_TIME_WINDOW
                self.colordata[i] = QColor(self.ACTIVE_FUNCTION_COLOR[0], self.ACTIVE_FUNCTION_COLOR[1],
                                           self.ACTIVE_FUNCTION_COLOR[2], int(alpha * recency_percent))
            else:
                self.colordata[i] = None

        if len(self.data) != len(self.colordata):
            l.error("ERROR CALCULATING COLOR DATA!")

        return new_rows

class FunctionTableFilterLineEdit(QLineEdit):
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
    def __init__(self, controller: BinSyncController, filteredit: FunctionTableFilterLineEdit, parent=None):
        super().__init__(parent=parent)

        self.controller = controller

        self.filteredit = filteredit
        self.filteredit.textChanged.connect(self.handle_filteredit_change)

        self.proxymodel = QSortFilterProxyModel()
        self.proxymodel.setSortRole(FunctionTableModel.SortRole)
        self.proxymodel.setFilterKeyColumn(1)

        self.model = FunctionTableModel(controller)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        self.doubleClicked.connect(self._doubleclick_handler)

        self.column_visibility = []

        self._init_settings()

    def _doubleclick_handler(self):
        # Doubleclick only allows for a single item select so just take first one from list
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        row = self.model.data[tls_row_idx.row()]
        self.controller.goto_address(row[0])

    def _get_valid_users_for_func(self, func_addr):
        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            user_func = user_state.get_function(func_addr)

            # function must be changed by this user
            if not user_func or not user_func.last_change:
                continue

            yield user.name

    def _col_hide_handler(self, index):
        self.column_visibility[index] = not self.column_visibility[index]
        self.setColumnHidden(index, self.column_visibility[index])
        if self.column_visibility[index]:
            self.showColumn(index)
        else:
            self.hideColumn(index)

    def update_table(self):
        self.model.update_table()

    def reload(self):
        pass

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_function_table_context_menu")

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
            func_addr = self.model.data[idx.row()][0]
            user_name = self.model.data[idx.row()][2]

            menu.addSeparator()
            menu.addAction("Sync", lambda: self.controller.fill_function(func_addr, user=user_name))
            from_menu = menu.addMenu("Sync from...")

            for username in self._get_valid_users_for_func(func_addr):
                action = from_menu.addAction(username)
                action.triggered.connect(lambda chck, name=username: self.controller.fill_function(func_addr, user=name))

        menu.popup(self.mapToGlobal(event.pos()))

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
        self.proxymodel.setFilterFixedString(text)

class QFunctionTable(QWidget):
    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.filteredit = FunctionTableFilterLineEdit(parent=self)
        self.table = FunctionTableView(self.controller, self.filteredit, parent=self)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.setContentsMargins(0,0,0,0)
        self.setLayout(layout)

    def update_table(self):
        self.table.update_table()

    def reload(self):
        pass
