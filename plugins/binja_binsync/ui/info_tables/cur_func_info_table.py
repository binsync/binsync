from collections import defaultdict
from typing import Dict

from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView
from PySide2.QtCore import Qt, QItemSelectionModel

import binsync
from ...controller import BinsyncController
from binsync.data import Function


class QUserItem(object):
    def __init__(self, user, last_push):
        self.user = user
        self.last_push = last_push

    def widgets(self):

        widgets = [
            QTableWidgetItem(self.user),
            QTableWidgetItem(self.last_push),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


class QCurFuncInfoTable(QTableWidget):

    HEADER = [
        'User',
        'Last Push',
    ]

    def __init__(self, controller, parent=None):
        super(QCurFuncInfoTable, self).__init__(parent)

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

        self.controller: BinsyncController = controller

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
            user_name = self.items[item_idx].user
        else:
            user_name = None
        return user_name

    def select_user(self, user_name):
        for i, item in enumerate(self.items):
            if item.user.name == user_name:
                self.selectRow(i)
                break

    def update_users(self, users):
        """
        Update the status of all users within the repo.
        """

        # reset the items in table
        self.items = []
        cur_binja_func = self.controller.current_function()
        if not cur_binja_func:
            return

        cuf_func_addr = int(cur_binja_func.start)

        rows = list()
        for user in users:
            user_state = self.controller.client.get_state(user=user.name)

            try:
                user_func = user_state.get_function(cuf_func_addr)
            except KeyError:
                continue

            row = [
                user.name,
                user_func.last_change
            ]

            rows.append(row)

        rows.sort(key=lambda i: i[1], reverse=True)

        for row in rows:
            # fix datetimes for the correct format
            if row[1] == -1:
                row[1] = ""
            else:
                row[1] = BinsyncController.friendly_datetime(row[1])

            table_row = QUserItem(*row)
            self.items.append(table_row)

        self.reload()
