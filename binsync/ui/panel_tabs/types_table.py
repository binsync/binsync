import logging
import datetime
from collections import defaultdict
import time

from declib.artifacts import Struct, Enum, Typedef

from binsync.controller import BSController
from binsync.ui.panel_tabs.table_model import BinsyncTableModel, BinsyncTableFilterLineEdit, BinsyncTableView
from declib.ui.qt_objects import (
    QMenu,
    QAction,
    QWidget,
    QVBoxLayout,
    Qt,
)
from binsync.ui.utils import friendly_datetime
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


_KIND_TO_ARTIFACT = {
    "Struct": Struct,
    "Enum": Enum,
    "Typedef": Typedef,
}
_KIND_TO_GETTER = {
    "Struct": "get_struct",
    "Enum": "get_enum",
    "Typedef": "get_typedef",
}


class TypesTableModel(BinsyncTableModel):
    """Activity model for structs, enums, and typedefs (name-keyed)."""

    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None,
                 addr_col=None, parent=None):
        super().__init__(controller, col_headers, filter_cols, time_col, addr_col, parent)
        self.data_dict = {}
        self.saved_color_window = self.controller.table_coloring_window
        self.context_menu_cache = {}

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()
        val = self.row_data[row][col]
        if role == Qt.DisplayRole:
            if col in (TypesTableView.COL_KIND, TypesTableView.COL_NAME, TypesTableView.COL_USER):
                return val
            elif col == TypesTableView.COL_DATE:
                return friendly_datetime(val) if val is not None else "—"
        elif role == self.SortRole:
            if col == self.time_col:
                if isinstance(val, datetime.datetime):
                    return time.mktime(val.timetuple())
                return 0
            return val
        elif role == Qt.BackgroundRole:
            return self.data_bgcolors[row]
        elif role == self.FilterRole:
            return " ".join((
                self.row_data[row][TypesTableView.COL_KIND] or "",
                self.row_data[row][TypesTableView.COL_NAME] or "",
                self.row_data[row][TypesTableView.COL_USER] or "",
            ))
        return None

    def update_table(self, states):
        cmenu_cache = defaultdict(list)
        updated_row_keys = set()

        for state in states:
            user_name = state.user
            sources = (
                (state.structs, "Struct"),
                (state.enums, "Enum"),
                (state.typedefs, "Typedef"),
            )
            for user_artifacts, kind in sources:
                for _, artifact in user_artifacts.items():
                    # Types loaded from the IDB type library don't fire per-artifact
                    # change events the way functions/globals do, so most arrive with
                    # last_change=None. Show them anyway and sort missing-time rows
                    # to the bottom.
                    change_time = artifact.last_change
                    key = f"{artifact.name}({kind})"
                    cmenu_cache[key].append(user_name)

                    existing = self.data_dict.get(key)
                    if existing is not None:
                        existing_time = existing[self.time_col]
                        if existing_time is not None and (
                            change_time is None or change_time <= existing_time
                        ):
                            continue

                    self.data_dict[key] = [kind, artifact.name, user_name, change_time]
                    updated_row_keys.add(key)

        self.context_menu_cache = cmenu_cache
        self._update_changed_rows(self.data_dict, updated_row_keys)
        self.refresh_time_cells()


class TypesTableView(BinsyncTableView):
    HEADER = ['Kind', 'Name', 'User', 'Last Push']
    COL_KIND = 0
    COL_NAME = 1
    COL_USER = 2
    COL_DATE = 3

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit, stretch_col=None,
                 col_count=None, parent=None):
        super().__init__(controller, filteredit, stretch_col, col_count, parent)

        self.model = TypesTableModel(
            controller, self.HEADER,
            filter_cols=[self.COL_KIND, self.COL_NAME, self.COL_USER],
            time_col=self.COL_DATE, parent=parent,
        )
        self.proxymodel.setSourceModel(self.model)
        self.setModel(self.proxymodel)
        self._init_settings()

    def _get_valid_users_for_type(self, type_name, kind):
        cache_key = f"{type_name}({kind})"
        if cache_key in self.model.context_menu_cache:
            for user_name in self.model.context_menu_cache[cache_key]:
                yield user_name
            return

        getter_name = _KIND_TO_GETTER.get(kind)
        if getter_name is None:
            return

        for user in self.controller.client.check_cache_(self.controller.client.users,
                                                        priority=SchedSpeed.FAST, fetch_cache=True):
            cache_item = self.controller.client.check_cache_(self.controller.client.get_state, user=user.name,
                                                              priority=SchedSpeed.FAST)
            if cache_item is None:
                continue
            getter = getattr(cache_item, getter_name)
            user_artifact = getter(type_name)
            if not user_artifact or not user_artifact.last_change:
                continue
            yield user.name

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_types_table_context_menu")

        valid_row = True
        selected_row = self.rowAt(event.pos().y())
        idx = self.proxymodel.index(selected_row, 0)
        idx = self.proxymodel.mapToSource(idx)
        if event.pos().y() == -1 and event.pos().x() == -1:
            idx = self.proxymodel.index(0, 0)
            idx = self.proxymodel.mapToSource(idx)
        elif not (0 <= selected_row < len(self.model.row_data)) or not idx.isValid():
            valid_row = False

        col_hide_menu = menu.addMenu("Show Columns")
        handler = lambda ind: lambda: self._col_hide_handler(ind)
        for i, c in enumerate(self.HEADER):
            act = QAction(c, parent=menu)
            act.setCheckable(True)
            act.setChecked(self.column_visibility[i])
            act.triggered.connect(handler(i))
            col_hide_menu.addAction(act)

        if valid_row:
            kind = self.model.row_data[idx.row()][self.COL_KIND]
            type_name = self.model.row_data[idx.row()][self.COL_NAME]
            user_name = self.model.row_data[idx.row()][self.COL_USER]
            if kind is None or type_name is None or user_name is None:
                menu.popup(self.mapToGlobal(event.pos()))
                return

            artifact_cls = _KIND_TO_ARTIFACT.get(kind)
            if artifact_cls is None:
                l.warning("Invalid type kind: %s", kind)
                menu.popup(self.mapToGlobal(event.pos()))
                return

            filler_func = lambda username: lambda chk=False: self.controller.fill_artifact(
                type_name, artifact_type=artifact_cls, user=username
            )

            menu.addSeparator()
            action = menu.addAction("Sync")
            action.triggered.connect(filler_func(user_name))
            from_menu = menu.addMenu("Sync from...")
            for username in self._get_valid_users_for_type(type_name, kind):
                action = from_menu.addAction(username)
                action.triggered.connect(filler_func(username))

        menu.popup(self.mapToGlobal(event.pos()))

    def _doubleclick_handler(self):
        """Open the type in the decompiler."""
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        type_name = self.model.row_data[tls_row_idx.row()][self.COL_NAME]
        if type_name:
            self.controller.deci.gui_show_type(type_name)


class QTypesTable(QWidget):
    """Control panel tab listing per-user activity on structs, enums, and typedefs."""

    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):
        col_count = len([col for col in TypesTableView.__dict__ if col.startswith("COL_")])
        self.filteredit = BinsyncTableFilterLineEdit(parent=self)
        self.table = TypesTableView(self.controller, self.filteredit,
                                     stretch_col=TypesTableView.COL_NAME, col_count=col_count)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)
        layout.addWidget(self.filteredit)
        self.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def update_table(self, states):
        self.table.update_table(states)

    def reload(self):
        pass
