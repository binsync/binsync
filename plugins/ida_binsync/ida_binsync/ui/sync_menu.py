from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QHBoxLayout, QLabel, QPushButton, QGroupBox, \
    QMessageBox, QCheckBox, QWidget, QFileDialog, QApplication, QComboBox, QTableWidget, QTableWidgetItem, \
    QDialogButtonBox, QGridLayout, QHeaderView, QTableView, QAbstractItemView
import sip
import threading

import idaapi
import idautils

import binsync.data
from .. import compat
from ..controller import BinsyncController
from ..controller import UpdateTask


#
#   MenuDialog Box for Binsync Actions
#

class BinsyncMenuActionItem:
    SYNC_SELECTED_FUNCTIONS = "Sync Selected Functions"
    SYNC_ALL_FUNCTIONS = "Sync All Functions"
    SYNC_STRUCTS = "Sync All Structs"
    TOGGLE_AUTO_SYNC = "Toggle Auto-Sync"


class MenuDialog(QDialog):
    def __init__(self, controller, selected_functions, parent=None):
        super(MenuDialog, self).__init__(parent)

        self.controller = controller
        self.selected_functions = selected_functions

        self.select_table_widget = None
        self.all_table_widget = None
        self.active_table = None

        self._init_widget()

    def _init_widget(self):
        label = QLabel("Binsync Action")
        self.combo = QComboBox()
        self.combo.addItems([BinsyncMenuActionItem.SYNC_SELECTED_FUNCTIONS,
                             BinsyncMenuActionItem.SYNC_ALL_FUNCTIONS,
                             BinsyncMenuActionItem.SYNC_STRUCTS,
                             BinsyncMenuActionItem.TOGGLE_AUTO_SYNC])
        self.combo.currentTextChanged.connect(self._on_combo_change)

        # build two versions of the table
        # TODO: eventually remove this. Its a hack to show all the users
        # in the case that we want to pull structs directly
        self.select_table_widget = self._build_table_widget(
            self._build_menu_table_for_selected_funcs(self.selected_functions)
        )
        self.all_table_widget = self._build_table_widget(
            self._build_menu_table_for_all_users()
        )

        # hide one of the tables, make the other active
        self.all_table_widget.hide()
        self.active_table = self.select_table_widget

        box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            centerButtons=True,
            )
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)

        lay = QGridLayout(self)
        lay.addWidget(label, 0, 0)
        lay.addWidget(self.combo, 0, 1)
        lay.addWidget(self.select_table_widget, 1, 0, 1, 2)
        lay.addWidget(self.all_table_widget, 1, 0, 1, 2)
        lay.addWidget(box, 2, 0, 1, 2)

        self.resize(640, 240)

    #
    #   Table Builders
    #

    def _build_table_widget(self, menu_table):
        table_widget = QTableWidget(len(menu_table), 4)
        table_widget.setHorizontalHeaderLabels(
            "User;Last Push;Func Addr;Remote Name".split(";")
        )

        header = table_widget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        for item, row in zip(menu_table, range(len(menu_table))):
            user_item = QTableWidgetItem(item[0])
            push_item = QTableWidgetItem(item[1])
            func_item = QTableWidgetItem(item[2])
            func_name_item = QTableWidgetItem(item[3])
            table_widget.setItem(row, 0, user_item)
            table_widget.setItem(row, 1, push_item)
            table_widget.setItem(row, 2, func_item)
            table_widget.setItem(row, 3, func_name_item)

        # set more table properties
        table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        table_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table_widget.doubleClicked.connect(self._on_click)
        
        return table_widget

    def _on_click(self, index):
        self.active_table.selectRow(index.row())
        self.accept()

    def _build_menu_table_for_all_users(self):
        if self.controller.client.has_remote:
            self.controller.client.init_remote()

        menu_table = list()
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            artifact, push_time = state.get_last_push_for_artifact_type(binsync.ArtifactGroupType.FUNCTION)

            if artifact is None or push_time == -1:
                row = [user.name, push_time, "", ""]
            else:
                local_name = compat.get_func_name(artifact)
                func = hex(artifact)
                row = [user.name, push_time, func, local_name]
            menu_table.append(row)

        menu_table.sort(key=lambda r: r[1], reverse=True)
        for row in menu_table:
            if row[1] == -1:
                time_ago = ""
            else:
                time_ago = BinsyncController.friendly_datetime(row[1])
            row[1] = time_ago

        return menu_table

    def _build_menu_table_for_selected_funcs(self, selected_funcs):
        if self.controller.client.has_remote:
            self.controller.client.init_remote()

        # Build out the menu dictionary for the table
        menu_table = list()     # [username, push_time, func_addr, local_name]
        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)

            relevant_funcs = set(state.functions.keys()).intersection(selected_funcs)
            # only display users who worked on the selected functions
            if not relevant_funcs:
                continue

            latest_time, latest_func, remote_name = -1, -1, ""
            for func_addr in relevant_funcs:
                sync_func: binsync.data.Function = state.functions[func_addr]
                if sync_func.last_change > latest_time:
                    latest_time, latest_func, remote_name = sync_func.last_change, sync_func.addr, sync_func.name if sync_func.name else ""

            if latest_time == -1:
                continue

            #local_name = compat.get_func_name(latest_func)
            func = hex(latest_func)
            row = [user.name, latest_time, func, remote_name]

            menu_table.append(row)

        # sort
        menu_table.sort(key=lambda r: r[1], reverse=True)

        # fix each time
        for row in menu_table:
            time_ago = BinsyncController.friendly_datetime(row[1])
            row[1] = time_ago

        return menu_table

    #
    #   Action Selection Box Callback
    #

    def _on_combo_change(self, value):
        self._hide_all_tables()
        if value == BinsyncMenuActionItem.SYNC_SELECTED_FUNCTIONS or value == BinsyncMenuActionItem.TOGGLE_AUTO_SYNC:
            self.select_table_widget.show()
            self.active_table = self.select_table_widget
        else:
            self.all_table_widget.show()
            self.active_table = self.all_table_widget

    def _hide_all_tables(self):
        self.select_table_widget.hide()
        self.all_table_widget.hide()

    #
    #   External API
    #

    def get_selected_action(self):
        # defaults to "Sync"
        action = self.combo.currentText()

        selected_rows = self.active_table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return action, None

        selected_user = selected_rows[0].data()
        return action, selected_user

#
#   IDA Context Menu Hook
#


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS

#
#   Actions
#


class SyncMenu:
    def __init__(self, controller):
        self.controller: BinsyncController = controller
        self.ctx_menu = IDACtxEntry(self.open_sync_menu)

    def open_sync_menu(self):
        """
        Opens sync menu and gives the optinal actions
        """
        selected_functions = self._get_selected_funcs()

        # open a dialog to make sync actions
        dialog = MenuDialog(self.controller, selected_functions)
        result = dialog.exec_()

        # only parse the action if the user accepted the result
        if result != QDialog.Accepted:
            return

        # parse action
        action, user = dialog.get_selected_action()

        # for every selected function perform the action!
        for func_addr in selected_functions:
            ida_func = idaapi.get_func(func_addr)
            ret = self._do_action(action, user, ida_func)
            if not ret:
                return

    def _do_action(self, action, user, ida_func):
        if user is None:
            print(f"[BinSync]: Error! No user selected for syncing.")
            return False

        if action == BinsyncMenuActionItem.SYNC_SELECTED_FUNCTIONS:
            cursor_at_func = compat.get_function_cursor_at()

            # if currently looking at a function, do a fill now
            if ida_func and cursor_at_func == ida_func.start_ea:
                self.controller.fill_function(ida_func.start_ea, user=user)

            # otherwise, do it later
            else:
                if ida_func and ida_func.start_ea:
                    try:
                        target_user_state = self.controller.client.get_state(user=user)
                        target_func = target_user_state.get_function(ida_func.start_ea)
                        remote_name = target_func.name

                        if remote_name != "" and remote_name:
                            compat.set_ida_func_name(ida_func.start_ea, remote_name)
                    except Exception:
                        pass

                update_task = UpdateTask(
                    self.controller.fill_function,
                    ida_func.start_ea, user=user
                )
                print(f"[BinSync]: Caching sync for \'{user}\' on function {hex(ida_func.start_ea)}.")
                self.controller.update_states[ida_func.start_ea].add_update_task(update_task)

        elif action == BinsyncMenuActionItem.TOGGLE_AUTO_SYNC:
            update_task = UpdateTask(
                self.controller.fill_function,
                ida_func.start_ea, user=user
            )
            print(f"[BinSync]: Toggling auto-sync for user \'{user}\' in function {hex(ida_func.start_ea)}.")
            self.controller.update_states[ida_func.start_ea].toggle_auto_sync_task(update_task)

        elif action == BinsyncMenuActionItem.SYNC_ALL_FUNCTIONS:
            threading.Thread(target=self.controller.sync_all, kwargs={"user": user}).start()
            #self.controller.sync_all(user=user)
            print(f"[BinSync]: All data has been synced from user: {user}.")

        elif action == BinsyncMenuActionItem.SYNC_STRUCTS:
            self.controller.fill_structs(user=user)
            print(f"[BinSync]: All structs have been synced from user: {user}")

        else:
            print(f"[BinSync]: Error parsing sync action!")
            return False

        return True

    def _get_selected_funcs(self):
        """
        Return the list of function names selected in the Functions window.

        Warning:
        It's possible that we don't get the correct name for a function lookup. In that case,
        this function will fail. See: https://github.com/gaasedelen/prefix/blob/master/plugin/ida_prefix.py#L567

        """
        twidget = idaapi.find_widget("Functions window")
        widget = sip.wrapinstance(int(twidget), QWidget)

        if not widget:
            idaapi.warning("Unable to find 'Functions window'")
            return

        #
        # locate the table widget within the Functions window that actually holds
        # all the visible function metadata
        #

        table: QTableView = widget.findChild(QTableView)

        #
        # scrape the selected function names from the Functions window table
        #
        selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]
        selected_func_addrs = [idaapi.get_name_ea(idaapi.BADADDR, func_name) for func_name in selected_funcs]
        return selected_func_addrs
