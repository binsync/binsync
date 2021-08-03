from collections import defaultdict
from typing import Dict

from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView
from PyQt5.QtCore import Qt, QItemSelectionModel

from ...controller import BinsyncController
from ... import compat
from binsync.data import Function


class QUserItem(object):
    def __init__(self, local_name, user, last_pull):
        self.local_name = local_name
        self.user = user
        self.last_pull = last_pull

    def widgets(self):

        u = self.user

        widgets = [
            QTableWidgetItem(self.local_name),
            QTableWidgetItem(u), #normally u.name
            QTableWidgetItem(self.last_pull),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


class QAutoSyncInfoTable(QTableWidget):

    HEADER = [
        'Function',
        'User',
        'Last Sync',
    ]

    def __init__(self, controller, parent=None):
        super(QAutoSyncInfoTable, self).__init__(parent)

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

        self.controller = controller

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

    def update_table(self):
        """
        Update the status of all users within the repo.
        """
        # reset the items in table
        self.items = []
        known_funcs = {}  # addr: (addr, name, user_name, push_time)
        for user,funcs in self.controller.autosync_store.items():
            for func in funcs:
                fname = compat.get_func_name(func.start_ea)
                if fname in self.controller.autosync_store_lastchange.keys():
                    time_delta = self.controller.friendly_datetime(self.controller.autosync_store_lastchange[fname])
                else:
                    time_delta = "None"
                table_row = QUserItem(fname, user, time_delta)
                self.items.append(table_row)
        self.reload()
