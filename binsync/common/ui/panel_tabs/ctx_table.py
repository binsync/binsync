import logging
import time
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
from binsync.common.ui.utils import friendly_datetime
from binsync.data import Function
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


class CTXTableModel(QAbstractTableModel):
    """Table model that controls backend behavior of the context table"""
    HEADER = [
        'User',
        'Remote Name',
        'Last Push'
        # 'Changes' temporarily disabled
    ]

    # Custom defined role for sorting (since we shouldn't sort hex numbers alphabetically)
    SortRole = Qt.UserRole + 1000

    # Color for most recently updated, the alpha value decreases linearly over controller.table_coloring_window
    ACTIVE_USER_COLOR = (100, 255, 100, 70)

    def __init__(self, controller: BinSyncController, data=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        # holds sublists of form: (user, remote name, push_time)
        self.row_data = data if data else []

        self.data_bgcolors = []

        self.ctx = None

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.row_data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return 3

    def data(self, index, role=Qt.DisplayRole):
        """ Returns information about the data at a specified index based
            on the role supplied. """
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            if index.column() == 0:
                return self.row_data[index.row()][0]
            elif index.column() == 1:
                return self.row_data[index.row()][1]
            elif index.column() == 2:
                return friendly_datetime(self.row_data[index.row()][2])
        elif role == CTXTableModel.SortRole:
            if index.column() == 0:
                return self.row_data[index.row()][0]
            elif index.column() == 1:
                return self.row_data[index.row()][1]
            elif index.column() == 2:
                return self.row_data[index.row()][2]
            elif index.column() == 3:
                if isinstance(self.row_data[index.row()][0], int):
                    return self.row_data[index.row()][3]
                elif isinstance(self.row_data[index.row()][0], datetime):
                    return time.mktime(self.row_data[index.row()][3].timetuple())
        elif role == Qt.BackgroundRole:
            if len(self.row_data) != len(self.data_bgcolors) or not (0 <= index.row() < len(self.data_bgcolors)):
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
            self.row_data.insert(position + row, ["USER", "LOADING", datetime.now()])
            self.data_bgcolors.insert(position + row, [QColor(0, 0, 0, 0)])

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.row_data) and 0 <= position + rows - 1 < len(self.row_data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)
            del self.row_data[position:position + rows]
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

        if index.isValid() and 0 <= index.row() < len(self.row_data):
            address = self.row_data[index.row()]
            if 0 <= index.column() < len(address):
                address[index.column()] = value
            else:
                return False
            self.dataChanged.emit(index, index)
            return True

        return False

    def flags(self, index):
        """ Set the item flags at the given index. """
        if not index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

    def entry_exists(self, user):
        """ Quick way to determine if an entry already exists via user """
        return user in [i[0] for i in self.row_data]

    def update_table(self, new_ctx=None):
        """ Updates the table using the controller's information """
        if self.ctx is None and new_ctx is None:
            return

        if new_ctx and self.ctx != new_ctx:
            self.ctx = new_ctx
            self.removeRows(0, rows=len(self.row_data))

        # for each user, iterate over all of their functions
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            func = state.get_function(self.ctx)
            if not func or not func.last_change:
                continue

            tab_idx = 0
            if self.entry_exists(user.name):
                tab_idx = [i[0] for i in self.row_data].index(user.name)
            else:
                self.insertRows(0)

            row_data = [user.name, func.name, func.last_change]
            for i in range(3):
                idx = self.index(tab_idx, i, QModelIndex())
                self.setData(idx, row_data[i], role=Qt.EditRole)

        # update table coloring, this might need to be checked for robustness
        now = datetime.now()
        for i in range(len(self.row_data)):
            t_upd = self.row_data[i][2]
            if isinstance(t_upd, int):
                if t_upd == -1:
                    self.data_bgcolors[i] = None
                t_upd = datetime.fromtimestamp(t_upd)

            duration = (now - t_upd).total_seconds()

            if 0 <= duration <= self.controller.table_coloring_window:
                alpha = self.ACTIVE_USER_COLOR[3]
                recency_percent = (self.controller.table_coloring_window - duration) / self.controller.table_coloring_window
                self.data_bgcolors[i] = QColor(self.ACTIVE_USER_COLOR[0], self.ACTIVE_USER_COLOR[1],
                                               self.ACTIVE_USER_COLOR[2], int(alpha * recency_percent))
            else:
                self.data_bgcolors[i] = None  # None will just cause no color changes from the default


class QCTXTable(QTableView):
    """ Table view for the data, this is the front end "container" for our model. """

    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent=parent)

        self.controller = controller

        # Create a SortFilterProxyModel to allow for sorting/filtering
        self.proxymodel = QSortFilterProxyModel()
        # Set the sort role/column to filter by
        self.proxymodel.setSortRole(CTXTableModel.SortRole)
        self.proxymodel.setFilterKeyColumn(-1)

        # Connect our model to the proxy model
        self.model = CTXTableModel(controller)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        self.column_visibility = []

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

    def _col_hide_handler(self, index):
        """ Helper function to hide/show columns from context menu """
        self.column_visibility[index] = not self.column_visibility[index]
        self.setColumnHidden(index, self.column_visibility[index])
        if self.column_visibility[index]:
            self.showColumn(index)
        else:
            self.hideColumn(index)

    def update_table(self, last_ctx=None):
        """ Update the model of the table with new data from the controller """
        self.model.update_table(last_ctx)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_context_table_context_menu")

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

        if valid_row and self.model.ctx:
            user_name = self.model.row_data[idx.row()][0]

            menu.addSeparator()
            menu.addAction("Sync", lambda: self.controller.fill_function(self.model.ctx, user=user_name))

        menu.popup(self.mapToGlobal(event.pos()))

    def _init_settings(self):
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setSortIndicator(0, Qt.AscendingOrder)
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)

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
