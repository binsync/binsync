import logging
from datetime import datetime

from binsync.common.controller import BinSyncController
from binsync.common.ui.qt_objects import (
    QAbstractItemView,
    QAbstractTableModel,
    QHeaderView,
    Qt,
    QModelIndex,
    QSortFilterProxyModel,
    QFocusEvent,
    QKeyEvent,
    QLineEdit,
    QTableView,
    QFontDatabase,
    QWidget,
    QVBoxLayout,
    QPersistentModelIndex,
    QCheckBox,
    QPushButton
)
from binsync.common.ui.utils import friendly_datetime

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

    def __init__(self, controller: BinSyncController, data=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        # holds sublists of form: (type, remote name, user, last push)
        self.row_data = data if data else []
        self.checks = [False for _ in self.row_data]
        self.gvar_name_to_addr_map = {}

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.row_data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return len(self.HEADER)

    def checkState(self, index):
        return Qt.Checked if self.checks[index.row()] else Qt.Unchecked

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
        elif role == Qt.CheckStateRole and index.column() == 0:
            return self.checkState(index)
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
            self.checks.insert(position + row, False)

        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.row_data) and 0 <= position + rows < len(self.row_data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)
            del self.row_data[position:position + rows]
            del self.checks[position:position+rows]
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
                self.checks[index.row()] = value
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
        if index.column() == 0:
            return Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled
        else:
            return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

    def update_table(self):
        decompiler_structs = self.controller.structs()
        decompiler_gvars = self.controller.global_vars()
        self.gvar_name_to_addr_map = {gvar.name: addr for addr, gvar in decompiler_gvars.items()}
        all_artifacts = [(decompiler_structs, "Struct"), (decompiler_gvars, "Variable")]
        
        for type_artifacts, type_ in all_artifacts:
            for _, artifact in type_artifacts.items():                      
                row = [type_, artifact.name or artifact.addr, "", -1]
                tab_idx = 0
                self.insertRows(0)
                for i in range(self.columnCount()):
                    idx = self.index(tab_idx, i, QModelIndex())
                    self.setData(idx, row[i], role=Qt.EditRole)


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
        self.select_all.setChecked(False)

    def _lookup_addr_for_gvar(self, name):
        return self.model.gvar_name_to_addr_map[name]

    def push(self):
        self.proxymodel.setFilterFixedString("")
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            if self.model.checkState(mappedIndex):
                type_ = self.model.data(mappedIndex)
                name = self.model.data(mappedIndex.sibling(mappedIndex.row(), 1))
                lookup_item = self._lookup_addr_for_gvar(name) if type_ == "Variable" else name
                self.controller.force_push_global_artifact(lookup_item)

    def connect_select_all(self, checkbox):
        self.select_all = checkbox

    def check_all(self):
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            self.model.setData(mappedIndex, True, Qt.CheckStateRole)

    def uncheck_all(self):
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            self.model.setData(mappedIndex, False, Qt.CheckStateRole)


class QGlobalsTable(QWidget):
    """ Wrapper widget to contain the globals table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def toggle_select_all(self):
        if self.checkbox.isChecked():
            self.table.check_all()
        else:
            self.table.uncheck_all()

    def _init_widgets(self):
        self.filteredit = GlobalTableFilterLineEdit(parent=self)
        self.table = GlobalTableView(self.controller, self.filteredit, parent=self)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.checkbox = QCheckBox("Select All")
        self.checkbox.clicked.connect(self.toggle_select_all)
        self.table.connect_select_all(self.checkbox)
        layout.addWidget(self.checkbox)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.push_button = QPushButton("Push")
        self.push_button.clicked.connect(self.table.push)
        layout.addWidget(self.push_button)

        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self):
        self.table.update_table()
