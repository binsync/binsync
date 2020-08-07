import datetime

from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PyQt5.QtCore import Qt


class QStatusItem(object):
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def friendly_value(self):
        if isinstance(self.value, str):
            return self.value
        if isinstance(self.value, datetime.datetime):
            return self.friendly_datetime(self.value)
        return str(self.value)

    @staticmethod
    def friendly_datetime(dt):
        now = datetime.datetime.now()
        if dt <= now:
            diff = now - dt
            ago = True
        else:
            diff = dt - now
            ago = False
        diff_days = diff.days
        diff_sec = diff.seconds

        if diff_days >= 1:
            s = "%d days" % diff_days
            ago = diff_days < 0
        elif diff_sec >= 60 * 60:
            s = "%d hours" % int(diff_sec / 60 / 60)
        elif diff_sec >= 60:
            s = "%d minutes" % int(diff_sec / 60)
        else:
            s = "%d seconds" % diff_sec

        s += " ago" if ago else " in the future"
        return s

    def widgets(self):

        widgets = [
            QTableWidgetItem(self.key),
            QTableWidgetItem(self.friendly_value()),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QStatusTable(QTableWidget):

    HEADER = [
        'Item',
        'Value',
    ]

    def __init__(self, controller, parent=None):
        super(QStatusTable, self).__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)

        self._controller = controller
        self.items = [ ]

        self._current_function = None
        self._status = None

    @property
    def current_function(self):
        return self._current_function

    @current_function.setter
    def current_function(self, v):
        self._current_function = v

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, v):
        self._status = v

    def reload(self):
        self.setRowCount(len(self.items))

        self.update()

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def update(self):
        """
        Initialize self.items based on information that is available to the controller.
        """

        self.items = [ ]

        # status
        self.items.append(QStatusItem('status', self.status))
        # current function
        self.items.append(QStatusItem('current function', self.current_function))

        try:
            status = self._controller.status()
        except RuntimeError:
            # not connected to any repo yet
            status = { }

        for k, v in status.items():
            self.items.append(QStatusItem(k, v))
