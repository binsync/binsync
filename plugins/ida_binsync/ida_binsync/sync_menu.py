from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QHBoxLayout, QLabel, QPushButton, QGroupBox, \
    QMessageBox, QCheckBox, QWidget, QFileDialog, QApplication, QComboBox, QTableWidget, QTableWidgetItem, \
    QDialogButtonBox, QGridLayout, QHeaderView, QTableView, QAbstractItemView
import sip
import idc
import idaapi
import idautils
from random import randint

from .controller import BinsyncController

#
#   MenuDialog Box for Binsync Actions
#

class MenuDialog(QDialog):
    def __init__(self, menu_table, parent=None):
        super(MenuDialog, self).__init__(parent)

        self.menu_table = menu_table

        label = QLabel("Binsync Action")
        self.combo = QComboBox()
        self.combo.addItems(["Sync", "Toggle autosync", "Toggle tracking"])
        self.combo.currentTextChanged.connect(self.on_combo_changed)


        self.tableWidget = QTableWidget(len(self.menu_table), 3)
        self.tableWidget.setHorizontalHeaderLabels(
            "User;Last Push;Last Edited Function".split(";")
        )

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        for item, row in zip(self.menu_table.items(), range(len(self.menu_table))):
            user_item = QTableWidgetItem(item[0])
            push_item = QTableWidgetItem(item[1][0])
            func_item = QTableWidgetItem(item[1][1])
            self.tableWidget.setItem(row, 0, user_item)
            self.tableWidget.setItem(row, 1, push_item)
            self.tableWidget.setItem(row, 2, func_item)

        # set more table properties
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)

        box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            centerButtons=True,
        )
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)

        lay = QGridLayout(self)
        lay.addWidget(label, 0, 0)
        lay.addWidget(self.combo, 0, 1)
        lay.addWidget(self.tableWidget, 1, 0, 1, 2)
        lay.addWidget(box, 2, 0, 1, 2)

        self.resize(640, 240)

    def getActionSelection(self):
        # defaults to "Sync"
        action = self.combo.currentText()

        selected_rows = self.tableWidget.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return action, None

        selected_row = selected_rows[0].row()
        selected_user = list(self.menu_table)[selected_row]
        return action, selected_user

    def on_combo_changed(self, value):
        if value == "Toggle tracking":
            self.tableWidget.hide()
        else:
            self.tableWidget.show()

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

class SyncMenu():
    def __init__(self, controller):
        self.controller: BinsyncController = controller
        self.ctx_menu = IDACtxEntry(self.open_sync_menu)

    def open_sync_menu(self):
        """
        Opens sync menu and gives the optinal actions
        """
        # create a dynamic menu table for the users
        menu_table = self._build_menu_table()

        # open a dialog to make sync actions
        dialog = MenuDialog(menu_table)
        result = dialog.exec_()

        # only parse the action if the user accepted the result
        if result != QDialog.Accepted:
            return

        # parse action
        action, user = dialog.getActionSelection()


        # for every selected function perform the action!
        for func_name in self._get_selected_funcs():
            func_addr = idaapi.get_name_ea(idaapi.BADADDR, func_name)
            ida_func = idaapi.get_func(func_addr)

            ret = self._do_action(action, user, ida_func)
            if ret == False:
                return

    def _do_action(self, action, user, ida_func):
        if action == "Sync":
            # confirm a selection has been made
            if user == None:
                print(f"[Binsync]: Error! No user selected for syncing.")
                return False

            self.controller.fill_function(ida_func, user=user)
            print(f"[Binsync]: Data has been synced from user: {user}.")
        elif action == "Toggle autosync":
            # confirm a selection has been made
            if user == None:
                print(f"[Binsync]: Error! No user selected for syncing.")
                return False

        elif action == "Toggle tracking":
            self.controller.push_function(ida_func)
            print(f"[Binsync]: function(s) toggled for tracking.")

        else:
            return False

        return True



    def _build_menu_table(self):
        """
        Builds a menu for use in the Dialog

        In the form of {user: (last_push, last_func_push)}
        :return:
        """

        menu_table = {}
        for user in self.controller.users():
            menu_table[user.name] = (f"{randint(0,60)} min ago", hex(randint(0xcafebabe, 0xdeadbeef)))

        return menu_table

    def _get_selected_funcs(self):
        """
        Return the list of function names selected in the Functions window.

        XXX:
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

        table = widget.findChild(QTableView)

        #
        # scrape the selected function names from the Functions window table
        #

        selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]
        return selected_funcs

