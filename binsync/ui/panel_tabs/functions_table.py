import datetime
import logging
import time
from typing import Dict
from collections import defaultdict

from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from libbs.ui.qt_objects import (
    QMenu,
    QAction,
    QWidget,
    QVBoxLayout,
    Qt,
    QToolTip,
    QCursor,
    QRect
)
from binsync.ui.utils import friendly_datetime
from binsync.core.scheduler import SchedSpeed
from libbs.artifacts import Function

l = logging.getLogger(__name__)


class FunctionTableModel(BinsyncTableModel):
    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.context_menu_cache = {}

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        col = index.column()
        row = index.row()
        if role == Qt.DisplayRole:
            if col == 0:
                return hex(self.row_data[row][col])
            elif col == 1 or col == 2:
                return self.row_data[row][col]
            elif col == 3:
                return friendly_datetime(self.row_data[row][col])
        elif role == self.SortRole:
            if col == self.time_col and isinstance(self.row_data[row][col], datetime.datetime):
                return time.mktime(self.row_data[row][col].timetuple())
            return self.row_data[row][col]
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return f"{hex(self.row_data[row][0])} {self.row_data[row][1]} {self.row_data[row][2]}"
        elif role == Qt.ToolTipRole:
            #return self.data_tooltips[index.row()]
            pass
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        # grab all the new info from user states
        for state in states:
            user_funcs: Dict[int, Function] = state.functions
            user_name = state.user
            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change
                # don't add functions that were never changed by the user
                if not func_change_time:
                    continue

                cmenu_cache[func_addr].append(user_name)

                # skip updating existent, older, functions
                if func_addr in self.data_dict and \
                        (not func_change_time or func_change_time <= self.data_dict[func_addr][self.time_col]):
                    continue

                self.data_dict[func_addr] = [
                    func_addr, sync_func.name if sync_func.name else "", user_name, func_change_time
                ]
                updated_row_keys.add(func_addr)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()

class FunctionTableView(BinsyncTableView):
    HEADER = ['Addr', 'Remote Name', 'User', 'Last Push']

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = FunctionTableModel(controller, self.HEADER, filter_cols=[0, 1], time_col=3, addr_col=0,
                                        parent=parent)
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)

        # always init settings *after* loading the model
        self._init_settings()

    def _get_valid_users_for_func(self, func_addr):
        """ Helper function for getting users that have changes in a given function """
        if func_addr in self.model.context_menu_cache:
            for username in self.model.context_menu_cache[func_addr]:
                yield username
        else:
            for user in self.controller.client.check_cache_(self.controller.client.users,
                                                            priority=SchedSpeed.FAST, no_cache=False):
                # only populate with cached items to prevent main thread waiting on atomic actions
                cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=user.name,
                                                                 priority=SchedSpeed.FAST)
                if cache_item is not None:
                    user_state = cache_item
                else:
                    continue

                user_func = user_state.get_function(func_addr)

                # function must be changed by this user
                if not user_func or not user_func.last_change:
                    continue

                yield user.name

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_function_table_context_menu")
        valid_row = True
        selected_row = self.rowAt(event.pos().y())
        idx = self.proxymodel.index(selected_row, 0)
        idx = self.proxymodel.mapToSource(idx)
        # support for automated tests
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

        if valid_row:
            func_addr = self.model.row_data[idx.row()][0]
            user_name = self.model.row_data[idx.row()][2]

            menu.addSeparator()
            if isinstance(func_addr, int) and func_addr > 0:
                sync_action = QAction("Sync", parent=menu)
                sync_action.triggered.connect( lambda: self.controller.fill_artifact(func_addr, artifact_type=Function, user=user_name))
                menu.addAction(sync_action)
                # menu.addAction("Sync", lambda: self.controller.fill_artifact(func_addr, artifact_type=Function, user=user_name))
                sync_action.hovered.connect(lambda: self.show_tooltip(func_addr, user_name))

            from_menu = menu.addMenu("Sync from...")
            users = self._get_valid_users_for_func(func_addr)
            for username in users:
                action = from_menu.addAction(username)
                action.triggered.connect(
                    lambda checked=False, name=username: self.controller.fill_artifact(func_addr, artifact_type=Function, user=name))
                action.hovered.connect(
                    lambda name=username: self.show_tooltip(func_addr, name))
        menu.popup(self.mapToGlobal(event.pos()))
        
    def show_tooltip(self, func_addr, user_name):
        """
        Have a popup box that shows the differences between the master and target function when hovering a sync option.

        Call preview_function_changes and parse the dictionary for any differences. Note this just applies to functions 
        and their comments. 
        """

        self.setStyleSheet("""
        QToolTip {
            background-color: #fff;
            color: black;
            border: 1px solid gray;
            padding: 2px;
            max-width: 600px;
            font-family: monospace;
        }
        """)
        
        differences = self.controller.preview_function_changes(func_addr=func_addr, user=user_name)
        # print(f"Differences: {differences}")
        
        # This will hold all the HTML stuff that will go into the tooltip
        diff_sections = []
        
        # For every field kind of doing the same thing so helper function to keep it succint 
        # Takes in the field it is comparing (name, type, ...) and the two values for that field to compare
        def create_simple_diff(field_name, master_val, target_val):
            if master_val == target_val:
                return ""
            # At this point there is a difference so need to craft the HTML that summarizes the difference 
            html = f"<b>{field_name}:</b><br>"
            # Need to handle that if it relates to master function it should be in red and target in green 
            if master_val:
                html += f"<span style='color:red; background-color:#ffecec;'>- {master_val}</span><br>"
            return html + f"<span style='color:green; background-color:#eaffea;'>+ {target_val}</span><hr>"
        
        diff_sections.extend(filter(None, [
            create_simple_diff("Name", differences['name']['master'], differences['name']['target']),
            create_simple_diff("Type", differences['type']['master'], differences['type']['target'])
        ]))
        
        # Args are a bit more tedious, first just go through master and targer and put together lists of relevant arg details 
        if differences['args']['master'] != differences['args']['target']:
            master_args = [f"{k} {arg.type} {arg.name}" if arg.type else f"{k} {arg.name}" 
                        for k, arg in differences['args']['master'].items()]
            target_args = [f"{k} {arg.type} {arg.name}" if arg.type else f"{k} {arg.name}" 
                        for k, arg in differences['args']['target'].items()]
            
            # Only show the args that differ between master and target 
            unique_args = set(master_args) ^ set(target_args)
            if unique_args:
                args_html = "<b>Args:</b>"
                for arg in unique_args:
                    # Just another approach for handling the different color appearances for master and target 
                    highlight = "eaffea" if arg in target_args else "ffecec"
                    color = "red" if arg in master_args else "green"
                    symbol = "-" if arg in master_args else "+"
                    args_html += f"<br><span style='color:{color}; background-color:#{highlight};'>{symbol} {arg}</span>"
                diff_sections.append(args_html + "<hr>")
        
        # For comments, just show comments in target that are not also in master (this differs from what args are shown)
        target_comments = differences['comments']['target'].items()
        master_comments = differences['comments']['master'].items()
        if not set(target_comments).issubset(set(master_comments)):
            comments_html = "<b>Comments:</b>"
            for key, value in target_comments:
                if key not in differences['comments']['master'] or differences['comments']['master'][key] != value:
                    comments_html += f"<br><span style='color:green; background-color:#eaffea;'>+ @{key}: {value}</span>"
            diff_sections.append(comments_html + "<hr>")
        
        diff_html = "".join(diff_sections) if diff_sections else "<span style='color:red; background-color:#ffecec;'>No changes</span>"
        
        QToolTip.showText(QCursor.pos(), diff_html, self, QRect(), 3000)

class QFunctionTable(QWidget):
    """ Wrapper widget to contain the function table classes in one file (prevents bulking up control_panel.py) """

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = FunctionTableView(self.controller, self.filteredit, stretch_col=1, col_count=4)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self, states):
        self.table.update_table(states)

    def reload(self):
        pass
