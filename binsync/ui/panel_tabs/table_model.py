import logging
import datetime
from typing import Dict, Set

from binsync.controller import BSController
from libbs.ui.qt_objects import (
    QAbstractItemView,
    QAbstractTableModel,
    QHeaderView,
    Qt,
    QModelIndex,
    QSortFilterProxyModel,
    QColor,
    QFocusEvent,
    QKeyEvent,
    QLineEdit,
    QTableView,
    QFontDatabase,
    Signal,
    Slot,
    QToolTip,
    QCursor,
    QRect
)

l = logging.getLogger(__name__)


class BinsyncTableModel(QAbstractTableModel):
    # Custom defined role for sorting/filtering (since we shouldn't sort hex numbers alphabetically)
    SortRole = Qt.UserRole + 1000
    FilterRole = Qt.UserRole + 1001

    # Color for most recently updated, the alpha value decreases linearly over controller.table_coloring_window
    ACTIVE_FUNCTION_COLOR = (100, 255, 100, 70)

    update_signal = Signal(list, list)

    def __init__(self, controller: BSController, col_headers=None, filter_cols=None, time_col=None, addr_col=None, parent=None):
        """
        Template class for a Binsync Table

        :param controller:    BinSyncController instance
        :param col_headers:   List of column header names
        :param col_dtypes:    List of data types (corresponding to the header names), supported
                              dtypes are {str, int, "time", "hex"}.
        :param addr_col:      (optional) Index of column containing addresses (if applicable)
        :param time_col:      (optional) Index of column containing times (if applicable)
        :param parent:        (optional) QT parent
        """
        super().__init__(parent)
        self.controller = controller
        self.row_data = []
        self.data_bgcolors = []
        self.data_tooltips = []

        self.col_headers = col_headers

        self.time_col = time_col
        self.addr_col = addr_col

        if isinstance(filter_cols, int):
            self.filter_cols = [filter_cols]
        else:
            self.filter_cols = filter_cols

        self.update_signal.connect(self.update_data)
        self.saved_color_window = self.controller.table_coloring_window

    def rowCount(self, index=QModelIndex()):
        """ Returns number of rows the model holds. """
        return len(self.row_data)

    def columnCount(self, index=QModelIndex()):
        """ Returns number of columns the model holds. """
        return len(self.col_headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """ Set the headers to be displayed. """
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            if 0 <= section < len(self.col_headers):
                return self.col_headers[section]

        return None

    def insertRows(self, position, rows=1, index=QModelIndex()):
        """ Insert N (default=1) rows into the model at a desired position. """
        self.beginInsertRows(QModelIndex(), position, position + rows - 1)
        for row in range(rows):
            self.row_data.insert(position + row, [0]*self.columnCount())
            self.data_bgcolors.insert(position + row, [QColor(0, 0, 0, 0)])
        self.endInsertRows()
        return True

    def removeRows(self, position, rows=1, index=QModelIndex()):
        """ Remove N (default=1) rows from the model at a desired position. """
        if 0 <= position < len(self.row_data) and 0 <= position + rows < len(self.row_data):
            self.beginRemoveRows(QModelIndex(), position, position + rows - 1)
            del self.row_data[position:position + rows]
            del self.data_bgcolors[position:position + rows]
            self.endRemoveRows()
            return True
        return False

    def setData(self, index, value, role=Qt.EditRole):
        """ Adjust the data (set it to <value>) depending on the given
            index and role. """
        if role != Qt.EditRole:
            return False
        if index.isValid() and 0 <= index.row() < len(self.row_data):
            address = self.row_data[index.row()]
            if 0 <= index.column() < len(address):
                address[index.column()] = value
            else:
                return False
            self.dataChanged.emit(index, index)
            return True
        return False

    @Slot(list, list)
    def update_data(self, new_data, new_colors):
        prev_rc = len(self.row_data)
        new_rc = len(new_data)
        adding = prev_rc < new_rc
        removing = new_rc < prev_rc
        if adding:
            self.beginInsertRows(QModelIndex(), prev_rc, new_rc-1)
        elif removing:
            self.beginRemoveRows(QModelIndex(), new_rc, prev_rc-1)

        self.row_data = new_data
        self.data_bgcolors = new_colors

        if adding:
            self.endInsertRows()
        elif removing:
            self.endRemoveRows()

    def flags(self, index):
        """ Set the item flags at the given index. """
        if not index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemFlags(QAbstractTableModel.flags(self, index))

    def data(self, index, role=Qt.DisplayRole):
        """ Returns information about the data at a specified index based
            on the role supplied. This function is performance sensitive. """
        raise NotImplementedError

    def refresh_time_cells(self):
        # always update every column in the table that contains time
        self.dataChanged.emit(
            self.createIndex(0, self.time_col),
            self.createIndex(self.rowCount() - 1, self.time_col)
        )

    def _update_changed_rows(self, row_data: Dict, updated_row_keys: Set):
        # user may have changed how dark he wants colors to go (color window)
        force_color_update = self.controller.table_coloring_window != self.saved_color_window

        # no changes are required
        if not updated_row_keys and not force_color_update:
            return False

        row_colors = [
            self._compute_row_color(row[self.time_col]) for row in row_data.values()
        ]

        if force_color_update:
            # update all rows
            self.saved_color_window = self.controller.table_coloring_window
            row_update_idxs = range(len(row_data))
        else:
            # update only rows with changes
            row_update_idxs = [
                idx for idx, row_key in enumerate(row_data.keys())
                if row_key in updated_row_keys
            ]

        # send update signal for everything in row data, with new colors
        self.update_signal.emit(list(row_data.values()), row_colors)

        # ask for in-row updates (in UI) to any single row changed
        for update_idx in row_update_idxs:
            self.dataChanged.emit(self.index(0, update_idx), self.index(self.rowCount() - 1, update_idx))

    def _compute_row_color(self, artifact_update_time: datetime.datetime):
        duration = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp() - artifact_update_time.timestamp())
        if 0 <= duration <= self.controller.table_coloring_window:
            opacity = (self.controller.table_coloring_window - duration) / self.controller.table_coloring_window
            return QColor(
                BinsyncTableModel.ACTIVE_FUNCTION_COLOR[0],
                BinsyncTableModel.ACTIVE_FUNCTION_COLOR[1],
                BinsyncTableModel.ACTIVE_FUNCTION_COLOR[2],
                int(BinsyncTableModel.ACTIVE_FUNCTION_COLOR[3] * opacity)
            )

        return None

    def update_table(self, states):
        """ Updates the table using the controller's information. """
        raise NotImplementedError


class BinsyncTableFilterLineEdit(QLineEdit):
    """ Basic class for the filter line edit, clears itself whenever focus is lost. """

    def __init__(self, parent=None):
        super(BinsyncTableFilterLineEdit, self).__init__(parent=parent)
        self.user_unfocused = False

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.user_unfocused:
            self.user_unfocused = False
            self.clear()

        if event.key() == Qt.Key_Escape:
            self.clear()
            return
        super(BinsyncTableFilterLineEdit, self).keyPressEvent(event)

    def focusOutEvent(self, event: QFocusEvent) -> None:
        if event.reason() == Qt.MouseFocusReason:
            self.user_unfocused = True
        super(BinsyncTableFilterLineEdit, self).focusOutEvent(event)


class BinsyncTableView(QTableView):
    """ Table view for the data, this is the front end "container" for our model. """

    def __init__(self, controller: BSController, filteredit: BinsyncTableFilterLineEdit=None, stretch_col=None, col_count=None, parent=None):
        """
        Template class for a Binsync Table View, required to create and set the model (extend BinsyncTableModel)

        :param controller:    BinSyncController instance
        :param filteredit:    An instance of BinsyncTableFilterLineEdit
        :param stretch_col:   Column to stretch (resize) when table is resized
        :param col_count:     Number of columns this table will have
        :param parent:        (optional) QT parent

        """
        super().__init__(parent=parent)

        self.controller = controller

        self.filteredit = filteredit
        if self.filteredit is not None:
            self.filteredit.textChanged.connect(self.handle_filteredit_change)

        # Create a SortFilterProxyModel to allow for sorting/filtering
        self.proxymodel = QSortFilterProxyModel()
        # Set the sort role/column to filter by
        self.proxymodel.setSortRole(BinsyncTableModel.SortRole)
        self.proxymodel.setFilterRole(BinsyncTableModel.FilterRole)
        self.proxymodel.setFilterKeyColumn(0)

        self.setModel(self.proxymodel)

        self.doubleClicked.connect(self._doubleclick_handler)
        self.column_visibility = []

        self.stretch_col = stretch_col
        self.col_count = col_count

    def _doubleclick_handler(self):
        """ Handler for double clicking on a row, jumps to the respective function. """
        if self.model.addr_col is None:
            return
        row_idx = self.selectionModel().selectedIndexes()[0]
        tls_row_idx = self.proxymodel.mapToSource(row_idx)
        row = self.model.row_data[tls_row_idx.row()]
        self.controller.deci.gui_goto(row[self.model.addr_col])

    def _col_hide_handler(self, index):
        """ Helper function to hide/show columns from context menu """
        self.column_visibility[index] = not self.column_visibility[index]
        self.setColumnHidden(index, self.column_visibility[index])
        if self.column_visibility[index]:
            self.showColumn(index)
        else:
            self.hideColumn(index)

    def update_table(self, states):
        """ Update the model of the table with new data from the controller """
        self.model.update_table(states)

    def reload(self):
        pass

    def contextMenuEvent(self, event):
        raise NotImplementedError

    def _init_settings(self):
        self.setShowGrid(False)

        header = self.horizontalHeader()
        header.setSortIndicator(0, Qt.AscendingOrder)
        for i in range(self.col_count):
            self.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(self.stretch_col, QHeaderView.Stretch)

        self.column_visibility = [True for _ in range(self.col_count)]

        fixed_width_font = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        fixed_width_font.setPointSize(11)
        self.setFont(fixed_width_font)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.setWordWrap(False)

        vheader = self.verticalHeader()
        vheader.setDefaultSectionSize(24)
        vheader.hide()

        self.setFocusProxy(self.filteredit)

    def handle_filteredit_change(self, text):
        """ Handle text changes in the filter box, filters the table by the arg. """
        self.proxymodel.setFilterFixedString(text)

    def render_tooltip_text(self, func_addr, user_name):
        differences = self.controller.preview_function_changes(func_addr=func_addr, user=user_name)
        # print(f"Differences: {differences}")

        # This will hold all the HTML stuff that will go into the tooltip
        diff_sections = []

        # For every field kind of doing the same thing so helper function to keep it succint
        # Takes in the field it is comparing (name, type, ...) and the two values for that field to compare
        def create_simple_diff(field_name, master_val, target_val):
            if master_val == target_val:
                return ""
            # At this point there is a difference so need to craft the HTML that summarizes the difference
            html = f"<b>{field_name}:</b><br>"
            # Need to handle that if it relates to master function it should be in red and target in green
            if master_val:
                html += f"<span style='color:red; background-color:#ffecec;'>- {master_val}</span><br>"
            return html + f"<span style='color:green; background-color:#eaffea;'>+ {target_val}</span><hr>"

        diff_sections.extend(filter(None, [
            create_simple_diff("Name", differences['name']['master'], differences['name']['target']),
            create_simple_diff("Type", differences['type']['master'], differences['type']['target'])
        ]))

        # Args are a bit more tedious, first just go through master and targer and put together lists of relevant arg details
        if differences['args']['master'] != differences['args']['target']:
            master_args = [f"{k} {arg.type} {arg.name}" if arg.type else f"{k} {arg.name}"
                           for k, arg in differences['args']['master'].items()]
            target_args = [f"{k} {arg.type} {arg.name}" if arg.type else f"{k} {arg.name}"
                           for k, arg in differences['args']['target'].items()]

            # Only show the args that differ between master and target
            unique_args = set(master_args) ^ set(target_args)
            if unique_args:
                args_html = "<b>Args:</b>"
                for arg in unique_args:
                    # Just another approach for handling the different color appearances for master and target
                    highlight = "eaffea" if arg in target_args else "ffecec"
                    color = "red" if arg in master_args else "green"
                    symbol = "-" if arg in master_args else "+"
                    args_html += f"<br><span style='color:{color}; background-color:#{highlight};'>{symbol} {arg}</span>"
                diff_sections.append(args_html + "<hr>")

        # For comments, just show comments in target that are not also in master (this differs from what args are shown)
        target_comments = differences['comments']['target'].items()
        master_comments = differences['comments']['master'].items()
        if not set(target_comments).issubset(set(master_comments)):
            comments_html = "<b>Comments:</b>"
            for key, value in target_comments:
                if key not in differences['comments']['master'] or differences['comments']['master'][key] != value:
                    comments_html += f"<br><span style='color:green; background-color:#eaffea;'>+ @{key}: {value}</span>"
            diff_sections.append(comments_html + "<hr>")

        diff_html = "".join(diff_sections) if diff_sections else "<span style='color:red; background-color:#ffecec;'>No changes</span>"
        return diff_html

    def show_tooltip(self, func_addr, user_name):
        """
        Have a popup box that shows the differences between the master and target function when hovering a sync option.

        Call preview_function_changes and parse the dictionary for any differences. Note this just applies to functions
        and their comments.
        """

        try:
            diff_html = self.render_tooltip_text(func_addr, user_name)
        except Exception:
            diff_html = None

        if diff_html:
            self.setStyleSheet("""
            QToolTip {
                background-color: #fff;
                color: black;
                border: 1px solid gray;
                padding: 2px;
                max-width: 600px;
                font-family: monospace;
            }
            """)
            QToolTip.showText(QCursor.pos(), diff_html, self, QRect(), 3000)
