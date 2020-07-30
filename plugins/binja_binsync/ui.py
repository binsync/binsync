from PySide2.QtWidgets import (
    QDockWidget,
    QWidget,
    QApplication,
    QMenu,
    QMainWindow,
    QTabWidget,
    QMenuBar,
    QDialog,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QHBoxLayout,
    QPushButton,
    QMessageBox,
    QGroupBox,
    QCheckBox,
)
from PySide2.QtCore import Qt


# Some code is derived from https://github.com/NOPDev/BinjaDock/tree/master/defunct
# Thanks @NOPDev


def find_main_window():
    main_window = None
    for x in QApplication.allWidgets():
        if not isinstance(x, QDockWidget):
            continue
        main_window = x.parent()
        if isinstance(main_window, (QMainWindow, QWidget)):
            break
        else:
            main_window = None

    if main_window is None:
        # oops cannot find the main window
        raise Exception("Main window is not found.")
    return main_window

class BinjaWidgetBase:
    def __init__(self):
        self._main_window = None
        self._menu_bar = None
        self._tool_menu = None

    @property
    def main_window(self):
        if self._main_window is None:
            self._main_window = find_main_window()
        return self._main_window

    @property
    def menu_bar(self):
        if self._menu_bar is None:
            self._menu_bar = next(
                iter(x for x in self._main_window.children() if isinstance(x, QMenuBar))
            )
        return self._menu_bar

    @property
    def tool_menu(self):
        if self._tool_menu is None:
            self._tool_menu = next(
                iter(
                    x
                    for x in self._menu_bar.children()
                    if isinstance(x, QMenu) and x.title() == u"Tools"
                )
            )
        return self._tool_menu

    def add_tool_menu_action(self, name, func):
        self.tool_menu.addAction(name, func)


class BinjaDockWidget(QDockWidget):
    def __init__(self, *args):
        super(BinjaDockWidget, self).__init__(*args)

        self.base = BinjaWidgetBase()

        self.base.add_tool_menu_action("Toggle plugin dock", self.toggle)
        # self._main_window.addDockWidget(Qt.RightDockWidgetArea, self)
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.East)
        self.setWidget(self._tabs)

        # self.hide()
        self.show()

    def toggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()


class BinjaWidget(QWidget):
    def __init__(self, tabname):
        super(BinjaWidget, self).__init__()
        # self._core = instance()
        # self._core.addTabWidget(self, tabname)
