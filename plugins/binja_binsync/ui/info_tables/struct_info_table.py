from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView
from PySide2.QtCore import Qt, QItemSelectionModel
from typing import Dict

from binsync.data import Struct
from ...controller import BinjaBinSyncController

class QUserItem:
    def __init__(self, struct_name, size, user, last_push):
        self.sturct_name = struct_name
        self.size = size
        self.user = user
        self.last_push = last_push

    def widgets(self):

        widgets = [
            QTableWidgetItem(self.sturct_name),
            QTableWidgetItem(hex(self.size)),
            QTableWidgetItem(self.user),
            QTableWidgetItem(self.last_push)
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


class QStructInfoTable(QTableWidget):

    HEADER = [
        'Struct Name',
        'Size',
        'User',
        'Last Push'
    ]

    def __init__(self, controller, parent=None):
        super(QStructInfoTable, self).__init__(parent)

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

    def update_users(self, users):
        """
        Update the status of all users within the repo.
        """

        # reset the items in table
        self.items = []
        known_structs = {} # struct_name: (struct_name, size, user_name, push_time)

        # first check if any functions are unknown to the table
        for user in users:
            try:
                state = self.controller.client.get_state(user=user.name)
                user_structs: Dict[str, Struct] = state.structs

                for struct_name, sync_struct in user_structs.items():
                    struct_change_time = sync_struct.last_change

                    if struct_change_time == -1:
                        continue

                    # check if we already know about it
                    if struct_name in known_structs:
                        # compare this users change time to the store change time
                        if struct_change_time < known_structs[struct_name][3]:
                            # don't change it if the other user is more recent
                            continue

                    known_structs[struct_name] = [struct_name, sync_struct.size, user.name, struct_change_time]
            except Exception:
                continue

        for row in known_structs.values():
            # fix datetimes for the correct format
            row[3] = BinjaBinSyncController.friendly_datetime(row[3])
            table_row = QUserItem(*row)
            self.items.append(table_row)

        self.reload()

