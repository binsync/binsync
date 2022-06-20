import logging
import re

from binsync.common.controller import BinSyncController
from binsync.common.ui.qt_objects import (
    QAbstractItemView,
    QHeaderView,
    QMenu,
    Qt,
    QTableWidget,
    QTableWidgetItem,
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
from binsync.core.state import State

l = logging.getLogger(__name__)


class QGlobalItem:
    def __init__(self, name, type_, user, last_push):
        self.name = name
        self.type = type_
        self.user = user
        self.last_push = last_push

    def widgets(self):
        # sort by int value
        name = QTableWidgetItem(self.name)
        type_ = QTableWidgetItem(self.type)
        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            name,
            type_,
            user,
            last_push
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QGlobalsTable(QTableWidget):
    HEADER = [
        'Name',
        'Type',
        'User',
        'Last Push'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QGlobalsTable, self).__init__(parent)
        self.controller = controller
        self.items = []

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignHCenter | Qt.Alignment(Qt.TextWordWrap))
        self.horizontalHeader().setMinimumWidth(160)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.setSortingEnabled(True)

    def reload(self):
        self.setSortingEnabled(False)
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()
        self.setSortingEnabled(True)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_global_table_context_menu")

        # create a nested menu
        selected_row = self.rowAt(event.pos().y())
        item0 = self.item(selected_row, 0)
        item1 = self.item(selected_row, 1)
        item2 = self.item(selected_row, 2)
        if any(x is None for x in [item0, item1, item2]):
            return
        global_name = item0.text()
        global_type = item1.text()
        user_name = item2.text()

        if global_type == "Struct":
            filler_func = lambda: self.controller.fill_struct(global_name, user=user_name)
        elif global_type == "Variable":
            var_addr = int(re.findall(r'0x[a-f,0-9]+', global_name.split(" ")[1])[0], 16)
            global_name = var_addr
            filler_func = lambda: self.controller.fill_global_var(global_name, user=user_name)
        elif global_type == "Enum":
            filler_func = lambda: self.controller.fill_enum(global_name, user=user_name)
        else:
            l.warning(f"Invalid global table sync option: {global_type}")
            return

        menu.addAction("Sync", filler_func)
        from_menu = menu.addMenu("Sync from...")
        for username in self._get_valid_users_for_global(global_name, global_type):
            from_menu.addAction(username, filler_func)

        menu.popup(self.mapToGlobal(event.pos()))

    def update_table(self):
        known_globals = {}

        for user in self.controller.users():
            state = self.controller.client.get_state(user=user.name)
            user_structs = state.structs
            user_gvars = state.global_vars
            user_enums = state.enums

            all_artifacts = ((user_enums, "Enum"), (user_structs, "Struct"), (user_gvars, "Variable"))
            for user_artifacts, global_type in all_artifacts:
                for _, artifact in user_artifacts.items():
                    change_time = artifact.last_change

                    if not change_time:
                        continue

                    if artifact.name in known_globals:
                        # change_time < artifact_stored_change_time
                        if not change_time or change_time < known_globals[artifact.name][3]:
                            continue

                    artifact_name = artifact.name if global_type != "Variable" \
                        else f"{artifact.name} ({hex(artifact.addr)})"

                    known_globals[artifact_name] = (artifact_name, global_type, user.name, change_time)

        self.items = [QGlobalItem(*row) for row in known_globals.values()]

    def _get_valid_users_for_global(self, global_name, global_type):
        if global_type == "Struct":
            global_getter = "get_struct"
        elif global_type == "Variable":
            global_getter = "get_global_var"
        elif global_type == "Enum":
            global_getter = "get_enum"
        else:
            l.warning("Failed to get a valid type for global type")
            return

        for user in self.controller.users(priority=1):
            user_state: State = self.controller.client.get_state(user=user.name, priority=1)
            get_global = getattr(user_state, global_getter)
            user_global = get_global(global_name)

            # function must be changed by this user
            if not user_global or not user_global.last_change:
                continue

            yield user.name
