from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PyQt5.QtCore import Qt


class QStatusItem(object):
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def widgets(self):

        widgets = [
            QTableWidgetItem(self.key),
            QTableWidgetItem(str(self.value)),
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
