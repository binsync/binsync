from .. import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PySide2.QtCore import Qt
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PySide6.QtCore import Qt
else:
    from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QMenu
    from PyQt5.QtCore import Qt

from . import QNumericItem

class QFunctionItem:
    def __init__(self, addr, name, user, last_push):
        self.addr = addr
        self.name = name
        self.user = user
        self.last_push = last_push

    def widgets(self):
        # sort by int value
        addr = QNumericItem(hex(self.addr))
        addr.setData(Qt.UserRole, self.addr)

        name = QTableWidgetItem(self.name)
        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(str(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            addr,
            name,
            user,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QFunctionTable(QTableWidget):

    HEADER = [
        'Addr',
        'Remote Name',
        'User',
        'Last Push'
    ]

    def __init__(self, controller, parent=None):
        super(QFunctionTable, self).__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.setSortingEnabled(True)

        self.items = [ ]
        self.controller = controller

        self.items = [
            QFunctionItem(0x1234, "dank", "zion", 1234567),
            QFunctionItem(0x11234, "dank", "emma", 1234567),
            QFunctionItem(0x901234, "dank", "davin", 1234567),
            QFunctionItem(0xAB1234, "dank", "kai", 1234567)
        ]
        self.reload()

    def reload(self):
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        showAction = menu.addAction("Show")

        if ui_version == "PyQt5":
            action = menu.exec(self.mapToGlobal(event.pos()))
        else:
            action = menu.exec_(self.mapToGlobal(event.pos()))

        if action == showAction:
            row = self.columnAt(event.pos().y())
            addr, username = self.item(row, 0), self.item(row, 2)
            print(addr.text(), username.text())

    def selected_user(self):
        try:
            idx = next(iter(self.selectedIndexes()))
        except StopIteration:
            # Nothing is selected
            return None
        item_idx = idx.row()
        if 0 <= item_idx < len(self.items):
            user_name = self.items[item_idx].user.name
        else:
            user_name = None
        return user_name

    def select_user(self, user_name):
        for i, item in enumerate(self.items):
            if item.user.name == user_name:
                self.selectRow(i)
                break

    def update_table(self, users):
        """
        Update the status of all users within the repo.
        """
        self.reload()
