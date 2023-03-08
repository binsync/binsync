import traceback
import sys
import logging

from PySide6.QtWidgets import (
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
import binaryninja
from binaryninjaui import DockContextHandler
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.mainthread import execute_on_main_thread, is_main_thread
from binaryninja.types import StructureType, EnumerationType

import binsync
from binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, FunctionArgument, StackVariable, StructMember, Struct,
    Comment, GlobalVariable, Patch, Enum, Struct, StructMember
)

# Some code is derived from https://github.com/NOPDev/BinjaDock/tree/master/defunct
# Thanks @NOPDev
l = logging.getLogger(__name__)


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


dockwidgets = [ ]


# shamelessly copied from https://github.com/Vector35/debugger
def create_widget(widget_class, name, parent, data, *args):
    # It is imperative this function return *some* value because Shiboken will try to deref what we return
    # If we return nothing (or throw) there will be a null pointer deref (and we won't even get to see why)
    # So in the event of an error or a nothing, return an empty widget that at least stops the crash
    try:
        # binsync specific code
        if not isinstance(data, binaryninja.BinaryView):
            raise Exception('expected an binary view')
        bv_controller = args[0][data]
        # uses only a bv_controller
        widget = widget_class(bv_controller, parent=parent, name=name, data=data)
        if not widget:
            raise Exception('expected widget, got None')

        global dockwidgets

        found = False
        for (bv, widgets) in dockwidgets:
            if bv == data:
                widgets[name] = widget
                found = True

        if not found:
            dockwidgets.append((data, {
                name: widget
            }))

        widget.destroyed.connect(lambda destroyed: destroy_widget(destroyed, widget, data, name))

        return widget
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return QWidget(parent)


def destroy_widget(destroyed, old, data, name):
    # Gotta be careful to delete the correct widget here
    for (bv, widgets) in dockwidgets:
        if bv == data:
            for (name, widget) in widgets.items():
                if widget == old:
                    # If there are no other references to it, this will be the only one and the call
                    # will delete it and invoke __del__.
                    widgets.pop(name)
                    return


class BinjaWidgetBase:
    def __init__(self):
        self._main_window = None
        self._menu_bar = None
        self._plugin_menu = None

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
    def plugin_menu(self):
        if self._plugin_menu is None:
            self._plugin_menu = next(
                iter(
                    x
                    for x in self._menu_bar.children()
                    if isinstance(x, QMenu) and x.title() == u"Plugins"
                )
            )
        return self._plugin_menu

    def add_tool_menu_action(self, name, func):
        self.plugin_menu.addAction(name, func)


class BinjaDockWidget(QWidget, DockContextHandler):
    def __init__(self, name, parent=None):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.base = BinjaWidgetBase()

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
        # self._core = _instance()
        # self._core.addTabWidget(self, tabname)

#
# Converters
#


def bn_struct_to_bs(name, bn_struct):
    members = {
        member.offset: StructMember(str(member.name), member.offset, str(member.type), member.type.width)
        for member in bn_struct.members if member.offset is not None
    }

    return Struct(
        str(name),
        bn_struct.width if bn_struct.width is not None else 0,
        members
    )


def bn_func_to_bs(bn_func):

    #
    # header: name, ret type, args
    #

    args = {
        i: FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), parameter.type.width)
        for i, parameter in enumerate(bn_func.parameter_vars)
    }

    sync_header = FunctionHeader(
        bn_func.name,
        bn_func.start,
        type_=bn_func.return_type.get_string_before_name(),
        args=args
    )

    #
    # stack vars
    #

    binja_stack_vars = {
        v.storage: v for v in bn_func.stack_layout if v.source_type == VariableSourceType.StackVariableSourceType
    }
    sorted_stack = sorted(bn_func.stack_layout, key=lambda x: x.storage)
    var_sizes = {}

    for off, var in binja_stack_vars.items():
        i = sorted_stack.index(var)
        if i + 1 >= len(sorted_stack):
            var_sizes[var] = 0
        else:
            var_sizes[var] = var.storage - sorted_stack[i].storage

    bs_stack_vars = {
        off: binsync.data.StackVariable(
            off,
            var.name,
            var.type.get_string_before_name(),
            var_sizes[var],
            bn_func.start
        )
        for off, var in binja_stack_vars.items()
    }

    size = bn_func.address_ranges[0].end - bn_func.address_ranges[0].start
    return Function(bn_func.start, size, header=sync_header, stack_vars=bs_stack_vars)
