from .. import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QTableWidgetItem
    from PySide2.QtCore import Qt
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QTableWidgetItem
    from PySide6.QtCore import Qt
else:
    from PyQt5.QtWidgets import QTableWidgetItem
    from PyQt5.QtCore import Qt


class QNumericItem(QTableWidgetItem):
    def __lt__(self, other):
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)
