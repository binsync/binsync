from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView
from PyQt5.QtCore import Qt, QItemSelectionModel


class QUserItem(object):
    def __init__(self, user):
        self.user = user

    def widgets(self):

        u = self.user

        widgets = [
            QTableWidgetItem(u.name),
            QTableWidgetItem(),
            QTableWidgetItem(),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QTeamTable(QTableWidget):

    HEADER = [
        'Edited functions',
        'Local function'
        # 'asd',
    ]

    def __init__(self, controller, parent=None):
        super(QTeamTable, self).__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) # so text does not get cut off
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.items = [ ]

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

    def update_users(self, users):

        selected_user = self.selected_user()

        self.items = [ ]

        for u in users:
            self.items.append(QUserItem(u))

        self.reload()

        if selected_user is not None:
            self.select_user(selected_user)