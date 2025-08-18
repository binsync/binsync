import logging
from typing import Dict, Set


from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from libbs.ui.qt_objects import (
    QWidget,
    QVBoxLayout,
    Qt,
    Signal,
    Slot,
    QModelIndex,
    QCheckBox,
    QPushButton,
    QAbstractTableModel
)
l = logging.getLogger(__name__)


class SegmentTableModel(BinsyncTableModel):
    update_signal = Signal(list)
    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.checks = {}

    def checkState(self, index):
        return Qt.Checked if self.checks[self.row_data[index.row()][0]] else Qt.Unchecked

    def checkStateBool(self, index):
        return True if self.checks[self.row_data[index.row()][0]] else False

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0:
                if isinstance(self.row_data[index.row()][0], int):
                    return f"{self.row_data[index.row()][0]:#x}"
                else:
                    return self.row_data[index.row()][0]
            elif col == 1:
                return f"{self.row_data[row][col]:#x}"
            elif col == 2:
                return f"{self.row_data[row][col]:#x}"
        elif role == self.SortRole:
            return self.row_data[row][col]
        elif role == self.FilterRole:
            return f"{self.row_data[row][0]:#x} {self.row_data[row][1]:#x} {self.row_data[row][2]}"
        elif role == Qt.CheckStateRole and index.column() == 0:
            return self.checkState(index)
        return None

    def setAllCheckStates(self, val):
        for k,v in self.checks.items():
            self.checks[k] = val
        self.dataChanged.emit(self.index(0, 0), self.index(self.rowCount() - 1, 0))

    def setData(self, index, value, role=Qt.EditRole):
        if role != Qt.EditRole and role != Qt.CheckStateRole:
            return False
        if index.isValid() and 0 <= index.row() < len(self.row_data):
            rowdata = self.row_data[index.row()]
            if role == Qt.CheckStateRole:
                self.checks[rowdata[0]] = value
            elif 0 <= index.column() < len(rowdata):
                rowdata[index.column()] = value
            else:
                return False
            self.dataChanged.emit(index, index)
            return True
        return False

    def update_table(self) -> None:
        updated_row_keys = set()
        self.controller.deci.info("Collecting Segment artifacts...")
        segment_by_name = {k: v for k, v in self.controller.deci.segments.items()}

        for name, segment in segment_by_name.items():
            self.data_dict[name] = [segment.name or "",  segment.start_addr, segment.end_addr]
            updated_row_keys.add(name)
            self.checks[name] = False
        self._update_changed_rows(self.data_dict, updated_row_keys)

    @Slot(list)
    def update_data(self, new_data):
        prev_rc = len(self.row_data)
        new_rc = len(new_data)
        adding = prev_rc < new_rc
        removing = new_rc < prev_rc
        if adding:
            self.beginInsertRows(QModelIndex(), prev_rc, new_rc - 1)
        elif removing:
            self.beginRemoveRows(QModelIndex(), new_rc, prev_rc - 1)

        self.row_data = new_data

        if adding:
            self.endInsertRows()
        elif removing:
            self.endRemoveRows()

    def _update_changed_rows(self, row_data: Dict, updated_row_keys: Set):

        # no changes are required
        if not updated_row_keys:
            return False

        row_update_idxs = [
            idx for idx, row_key in enumerate(row_data.keys())
            if row_key in updated_row_keys
        ]

        # send update signal for everything in row data, with new colors
        self.update_signal.emit(list(row_data.values()))

        # ask for in-row updates (in UI) to any single row changed
        for update_idx in row_update_idxs:
            self.dataChanged.emit(self.index(0, update_idx), self.index(self.rowCount() - 1, update_idx))

    def contextMenuEvent(self, event):
        pass

    def flags(self, index):
        """ Set the item flags at the given index. """
        if not index.isValid():
            return Qt.ItemIsEnabled
        if index.column() == 0:
            return Qt.ItemIsUserCheckable | Qt.ItemIsSelectable | Qt.ItemIsEnabled
        else:
            return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

class SegmentTableView(BinsyncTableView):
    HEADER = ['Name', 'Start', 'End']

    def __init__(
        self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None, col_count=None,
        parent=None
    ):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = SegmentTableModel(
            controller, self.HEADER, filter_cols=[0, 1, 2], addr_col=0, parent=parent
        )
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def update_table(self):
        self.model.update_table()

    def push(self):
        names_to_push = []
        first_state_obj = self.model.checkState(
            self.proxymodel.mapToSource(self.proxymodel.index(0, 0, QModelIndex()))
        )
        check_has_value = hasattr(first_state_obj, "value")

        self.proxymodel.setFilterFixedString("")
        for i in range(self.proxymodel.rowCount()):
            proxyIndex = self.proxymodel.index(i, 0, QModelIndex())
            mappedIndex = self.proxymodel.mapToSource(proxyIndex)
            model_state = self.model.checkState(mappedIndex)
            is_checked = model_state.value if check_has_value else model_state
            if is_checked:
                segment_name = self.model.data(mappedIndex)
                names_to_push.append(segment_name)

        self.controller.force_push_segments(names_to_push)

    def check_all(self):
        self.model.setAllCheckStates(True)

    def uncheck_all(self):
        self.model.setAllCheckStates(False)

    def _doubleclick_handler(self):
        """ Handler for double clicking on a row, toggles selection. """
        if self.model.addr_col is None:
            return
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)

        self.model.setData(tls_row_idx, not self.model.checkStateBool(tls_row_idx), role=Qt.CheckStateRole)


class QSegmentTable(QWidget):
    """ Wrapper widget to contain the segment table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def toggle_select_all(self):
        if self.checkbox.isChecked():
            self.table.check_all()
        else:
            self.table.uncheck_all()

    def _init_widgets(self):
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = SegmentTableView(
            self.controller, self.filteredit, stretch_col=2, col_count=3
        )
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.checkbox = QCheckBox("Select All")
        self.checkbox.clicked.connect(self.toggle_select_all)
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

    def reload(self):
        pass