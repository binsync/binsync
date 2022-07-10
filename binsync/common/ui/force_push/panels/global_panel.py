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
    QStyledItemDelegate,
    QFontDatabase,
    QAction,
    QEvent,
    QCheckBox
)
from binsync.common.ui.utils import QNumericItem, friendly_datetime
from binsync.data.state import State
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)

fixed_width_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
fixed_width_font.setPointSize(11)

class QGlobalItem:
    def __init__(self, name, type_, user, last_push):
        self.name = name
        self.type = type_
        self.user = user
        self.last_push = last_push

    def widgets(self):
        checked = QCheckBox("")
        # sort by int value
        name = QTableWidgetItem(self.name)
        type_ = QTableWidgetItem(self.type)
        user = QTableWidgetItem(self.user)

        # sort by unix value
        last_push = QNumericItem(friendly_datetime(self.last_push))
        last_push.setData(Qt.UserRole, self.last_push)

        widgets = [
            checked,
            type_,
            name,
            user,
            last_push
        ]

        for w in widgets[1:]:
            w.setFont(fixed_width_font)
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

class QGlobalsTableCenterAlignDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super(QGlobalsTableCenterAlignDelegate, self).initStyleOption(option, index)
        option.displayAlignment = Qt.AlignCenter


class QGlobalsTable(QTableWidget):
    HEADER = [
        '',
        'T',
        'Name',
        'User',
        'Last Push'
    ]

    def __init__(self, controller: BinSyncController, parent=None):
        super(QGlobalsTable, self).__init__(parent)
        self.controller = controller
        self.items = []

        self.setColumnCount(len(self.HEADER))
        self.column_visibility = [True for _ in range(len(self.HEADER))]
        self.setHorizontalHeaderLabels(self.HEADER)

        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.setColumnWidth(0, 16)
        self.setItemDelegateForColumn(0, QGlobalsTableCenterAlignDelegate(self))
        self.horizontalHeaderItem(0).setToolTip("Type")

        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)

        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignHCenter | Qt.Alignment(Qt.TextWordWrap))
        self.horizontalHeader().setMinimumWidth(160)
        self.horizontalHeader().setSortIndicator(3, Qt.AscendingOrder)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.NoSelection)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(22)


        self.setSortingEnabled(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)

    def reload(self):
        self.setSortingEnabled(False)
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                if i==0:
                    self.setCellWidget(idx, i, it)
                else:
                    self.setItem(idx, i, it)

        self.viewport().update()
        self.setSortingEnabled(True)

    def _col_hide_handler(self, index):
        self.column_visibility[index] = not self.column_visibility[index]
        self.setColumnHidden(index, self.column_visibility[index])
        if self.column_visibility[index]:
            self.showColumn(index)
        else:
            self.hideColumn(index)

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

                    known_globals[artifact_name] = (artifact_name, global_type[:1], user.name, change_time)

        self.items = [QGlobalItem(*row) for row in known_globals.values()]

    def _get_valid_users_for_global(self, global_name, global_type):
        if global_type == "Struct" or global_type == "S":
            global_getter = "get_struct"
        elif global_type == "Variable" or global_type == "V":
            global_getter = "get_global_var"
        elif global_type == "Enum" or global_type == "E":
            global_getter = "get_enum"
        else:
            l.warning("Failed to get a valid type for global type")
            return

        for user in self.controller.users(priority=SchedSpeed.FAST):
            user_state: State = self.controller.client.get_state(user=user.name, priority=SchedSpeed.FAST)
            get_global = getattr(user_state, global_getter)
            user_global = get_global(global_name)

            # function must be changed by this user
            if not user_global or not user_global.last_change:
                continue

            yield user.name
