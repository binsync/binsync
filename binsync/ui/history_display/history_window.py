import logging
from binsync.controller import BSController
from datetime import datetime, timezone, timedelta
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableView

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
    QFont
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
    def __init__(self,controller:BSController=None,parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()
        self._display_diff()
        
    def _init_widgets(self):
        self.setWindowTitle("History")
        
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        bottom_layout = QVBoxLayout()
        
        top_layout.addWidget(QLabel("Functions Changed in the Past Day"))
        
        self.table_view = HistoryTableView(self.controller)
        bottom_layout.addWidget(self.table_view)
        
        
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
        
        self.setLayout(main_layout)
        self.resize(1000, 800)
        
    def _display_diff(self):
        changed_functions = []
        client = self.controller.client
        previous_time =  (datetime.now(timezone.utc)-timedelta(days=1)).timestamp()
        old_commit = client.find_commit_before_ts(client.repo, previous_time,user_name=client.master_user)
        old_state = client.parse_state_from_commit(client.repo,commit_hash=old_commit)
        curr_state = self.controller.get_state()
        for addr, new_function in curr_state.functions.items():
            if addr not in old_state.functions:
                # Is this case possible?
                changed_functions.append(new_function)
            else:
                diffs = self._get_function_diffs(curr_state,old_state,addr)
                for diff_dict in diffs.values():
                    if diff_dict["master"] != diff_dict["target"]:
                        changed_functions.append(new_function)
                        break
        self.table_view.model.update_data(
            [(func.addr,func.name) for func in changed_functions],
            [QColor(0,0,0,0) for _ in changed_functions]
        )
    
    def _get_function_diffs(self,state1, state2, addr)->dict[str,dict[str,any]]:
        '''
        Copied from BSController.preview_function_changes
        
        Returns the diffs between a function at an address given two different states.
        
        @returns A Dict containing name, args, type, stack_vars, and comments that each map to a dict.
        Each mapped dict contains an entry for the first function "master" and the second function "target".
        '''
        get_comments = lambda state_obj: {addr: cmt.comment for addr, cmt in state_obj.get_func_comments(addr).items()}
        func1 = state1.functions[addr]
        func2 = state2.functions[addr]
        def get_header_attr(func, attr):
            return getattr(func.header, attr, None) if func and func.header else None
        diffs = {
            'name': {
                'master': func1.name if func1 else None,
                'target': func2.name if func2 else None
            },
            'args': {
                'master': get_header_attr(func1, 'args') or {},
                'target': get_header_attr(func2, 'args') or {}
            },
            'type': {
                'master': get_header_attr(func1, 'type'),
                'target': get_header_attr(func2, 'type')
            },
            'stack_vars': {
                'master': func1.stack_vars if func1 else {},
                'target': func2.stack_vars if func2 else {}
            },
            'comments': {
                'master': get_comments(state1),
                'target': get_comments(state2)
            }
        }
        return diffs
                