import logging
from binsync.controller import BSController
from datetime import datetime, timezone, timedelta
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableView
from binsync.core.client import SchedSpeed
from libbs.ui.qt_objects import (
    # QtWidgets
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QMenu,
    QAction,
    Qt,
    QColor,
    QComboBox,
    QLineEdit,
    QPushButton
)
l = logging.getLogger(__name__)

class HistoryTableModel(BinsyncTableModel):
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
            if col == self.addr_col:
                return hex(self.row_data[row][col])
            else:
                return self.row_data[row][col]
        elif role == self.SortRole:
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return self.row_data[row][0] + " " + self.row_data[row][1]
        elif role == Qt.ToolTipRole:
            #return self.data_tooltips[row]
            pass
        return None

    # No update_table because we don't care about the current state

class HistoryTableView(BinsyncTableView):
    HEADER = ['Addr', 'Function']

    def __init__(self, controller: BSController, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, None, 1, 2, parent)

        self.model = HistoryTableModel(controller, self.HEADER, addr_col=0,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_history_table_context_menu")

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

        menu.popup(self.mapToGlobal(event.pos()))

class HistoryDisplayWidget(QDialog):
    timescale_mapping = {
        "Minutes": "minutes",
        "Hours": "hours",
        "Days": "days",
        "Weeks": "weeks"
    }
    def __init__(self, controller:BSController=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()
        self._update_diff()
        
    def _init_widgets(self):
        self.setWindowTitle("History")
        
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        bottom_layout = QVBoxLayout()
        
        top_layout.addWidget(QLabel("Functions Changed in the Past "))

        self.timescale_time_widget = QLineEdit() 
        self.timescale_time_widget.setText("1")
        top_layout.addWidget(self.timescale_time_widget)

        self.timescale_type_widget = QComboBox()
        self.timescale_type_widget.addItems(list(HistoryDisplayWidget.timescale_mapping.keys()))
        self.timescale_type_widget.setCurrentText("Days")
        top_layout.addWidget(self.timescale_type_widget)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._update_diff_from_refresh)
        top_layout.addWidget(self.refresh_button)


        self.table_view = HistoryTableView(self.controller)
        bottom_layout.addWidget(self.table_view)
        
        
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
        
        self.setLayout(main_layout)
        self.resize(1000, 800)
    
    def _update_diff_from_refresh(self):
        self.refresh_button.setEnabled(False)
        self._update_diff()

    def _update_diff(self):
        """
        Calls _display_diff with the values provided in the input widgets
        """
        try:
            timescale_time = int(self.timescale_time_widget.text())
        except ValueError:
            return # Wait for an actual time value to be entered
        else:
            if timescale_time < 0:
                return # We can't see into the future

        timescale_type = self.timescale_type_widget.currentText()
        self._display_diff(timescale_options={
            HistoryDisplayWidget.timescale_mapping[timescale_type]: timescale_time
        })

    def _display_diff(self, timescale_options: dict[str, int]):
        changed_functions = []
        client = self.controller.client
        if client is None:
            l.error("Client is None when trying display diff")
            return
        previous_time =  (datetime.now(timezone.utc)-timedelta(**timescale_options)).timestamp()
        old_commit = client.find_commit_before_ts(client.repo, previous_time,user_name=client.master_user)
        # Because we're not grabbing from the newest commit we don't want to mess around with the cache
        old_state = client.get_state(priority = SchedSpeed.FAST, fetch_cache=False, save_cache=False, commit_hash=old_commit)
        
        curr_state = self.controller.get_state()
        
        for addr, new_function in curr_state.functions.items():
            if addr not in old_state.functions:
                # Is this case possible?
                changed_functions.append(new_function)
            else:
                diffs = curr_state.diff_function_artifacts(old_state, addr)
                for diff_dict in diffs.values():
                    if diff_dict["master"] != diff_dict["target"]:
                        changed_functions.append(new_function)
                        break
        self.table_view.model.update_data(
            [(func.addr,func.name) for func in changed_functions],
            [QColor(0,0,0,0) for _ in changed_functions]
        )
        self.refresh_button.setEnabled(True)
                