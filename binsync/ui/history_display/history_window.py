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
    QPushButton,
    QDateTimeEdit,
    QDateTime,
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
        
        top_layout.addWidget(QLabel("Functions Changed From "))

        self.from_date_widget = QDateTimeEdit()
        self.from_date_widget.setCalendarPopup(True)
        self.from_date_widget.setDateTime(QDateTime.currentDateTime().addDays(-1)) # 1 day before current time
        top_layout.addWidget(self.from_date_widget)

        top_layout.addWidget(QLabel("to"))

        self.to_date_widget = QDateTimeEdit()
        self.to_date_widget.setCalendarPopup(True)
        self.to_date_widget.setDateTime(QDateTime.currentDateTime())
        top_layout.addWidget(self.to_date_widget)


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
        self.refresh_button.setEnabled(True)

    def _update_diff(self):
        """
        Calls _display_diff with the values provided in the input widgets
        """
        old_time = self.from_date_widget.dateTime().toSecsSinceEpoch()
        new_time = self.to_date_widget.dateTime().toSecsSinceEpoch()
        if old_time >= new_time:
            # Wipe out table
            self.table_view.model.update_data( 
                [],
                []
            )
        else:
            self._display_diff(old_time=old_time, new_time=new_time)

    def _display_diff(self, old_time: int, new_time: int):
        changed_functions = []
        client = self.controller.client
        if client is None:
            l.error("Client is None when trying display diff")
            return

        old_commit = client.find_commit_before_ts(client.repo, old_time,user_name=client.master_user)
        # Because we're not grabbing from the newest commit we don't want to mess around with the cache
        old_state = client.get_state(priority = SchedSpeed.FAST, fetch_cache=False, save_cache=False, commit_hash=old_commit)
        
        new_commit = client.find_commit_before_ts(client.repo, new_time,user_name=client.master_user)
        # Because we're not grabbing from the newest commit we don't want to mess around with the cache
        new_state = client.get_state(priority = SchedSpeed.FAST, fetch_cache=False, save_cache=False, commit_hash=new_commit)
        
        for addr, new_function in new_state.functions.items():
            if addr not in old_state.functions:
                # Is this case possible?
                changed_functions.append(new_function)
            else:
                diffs = new_state.diff_function_artifacts(old_state, addr)
                for diff_dict in diffs.values():
                    if diff_dict["master"] != diff_dict["target"]:
                        changed_functions.append(new_function)
                        break
        self.table_view.model.update_data(
            [(func.addr,func.name) for func in changed_functions],
            [QColor(0,0,0,0) for _ in changed_functions]
        )
        