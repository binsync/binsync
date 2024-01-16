import logging
import datetime
import time

from libbs.artifacts import Function

from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableView
from libbs.ui.qt_objects import (
    QMenu,
    QAction,
    Qt
)
from binsync.ui.utils import friendly_datetime

l = logging.getLogger(__name__)


class CTXTableModel(BinsyncTableModel):
    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.saved_color_window = self.controller.table_coloring_window

        self.saved_ctx = None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0 or col == 1:
                return self.row_data[row][col]
            elif col == 2:
                return friendly_datetime(self.row_data[row][col])
        elif role == self.SortRole:
            if col == self.time_col and isinstance(self.row_data[row][col], datetime.datetime):
                return time.mktime(self.row_data[row][col].timetuple())
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return self.row_data[row][0] + " " + self.row_data[row][1]
        elif role == Qt.ToolTipRole:
            #return self.data_tooltips[row]
            pass
        return None

    def update_table(self, states, new_ctx=None):
        """ Updates the table using the controller's information """
        # we have never had a set context yet
        if self.saved_ctx is None and new_ctx is None:
            return

        # the context has updated
        if new_ctx and self.saved_ctx != new_ctx:
            self.saved_ctx = new_ctx
            self.data_dict = {}

        updated_row_keys = set()
        for state in states:
            user_name = state.user
            func = state.get_function(self.saved_ctx)
            if not func or not func.last_change:
                continue

            self.data_dict[user_name] = [user_name, func.name, func.last_change]
            updated_row_keys.add(user_name)

        # clear the entire table in the case of a new empty ctx
        if not self.data_dict:
            self.update_signal.emit([], [])
        else:
            self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()


class QCTXTable(BinsyncTableView):
    HEADER = ['User', 'Remote Name', 'Last Push']

    def __init__(self, controller: BSController, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, None, 1, 3, parent)

        self.model = CTXTableModel(controller, self.HEADER, filter_cols=[0, 1], time_col=2,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_context_table_context_menu")

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

        if valid_row and self.model.saved_ctx:
            user_name = self.model.row_data[idx.row()][0]

            menu.addSeparator()
            menu.addAction("Sync", lambda: self.controller.fill_artifact(self.model.saved_ctx, artifact_type=Function, user=user_name))

        menu.popup(self.mapToGlobal(event.pos()))

    def update_table(self, states, new_ctx=None):
        """ Update the model of the table with new data from the controller """
        self.model.update_table(states, new_ctx=new_ctx)