from .. import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView, \
        QStyledItemDelegate, QSpinBox
    from PySide2.QtCore import Qt
    from PySide2.QtGui import QFont
elif ui_version == "PySide6":
    pass
else:
    pass


class QFunctionItem(object):
    def __init__(self, addr, name, user, last_push):
        self.addr = addr
        self.name = name
        self.user = user
        self.last_push = last_push

    def widgets(self):
        addr = QTableWidgetItem(self.addr)
        addr.setData(Qt.DisplayRole, hex(self.addr))

        name = QTableWidgetItem(self.name)
        user = QTableWidgetItem(self.user)
        last_push = QTableWidgetItem(self.last_push)
        last_push.setText(str(self.last_push))

        widgets = [
            addr,
            name,
            user,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


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
