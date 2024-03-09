import os
import sys
import tempfile

import time
import logging
from datetime import datetime as datetime_, timedelta

from PySide6 import QtWidgets
from PySide6.QtGui import QContextMenuEvent
from PySide6.QtCore import Qt, QPoint
from PySide6.QtWidgets import QApplication, QMenu
from angrmanagement.ui.views import CodeView, DisassemblyView
from pytestqt.qtbot import QtBot
import pytest

import angr
from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.main_window import MainWindow

from libbs.ui.version import set_ui_version
set_ui_version("PySide6")
from binsync.controller import SyncControlStatus
from binsync.ui.config_dialog import ConfigureBSDialog


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'binaries')
logging.disable(logging.CRITICAL)

BINSYNC_RELOAD_TIME = 10000


def get_timestamp():
    return datetime_.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')


def qWait(to_wait, app):
    endtime = datetime_.now() + timedelta(milliseconds=to_wait)
    while datetime_.now() < endtime:
        app.processEvents()

def closeShim(event):
    event.ignore()

def start_am_gui(binpath, app):
    main = MainWindow(show=False, app=app)
    main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
    main.workspace.main_instance.project.am_event()
    main.workspace.main_instance.join_all_jobs()
    main.closeEvent = closeShim
    return main


def get_binsync_am_plugin(main):
    plugin_shortname = "binsync"
    binsync_plugin = main.workspace.plugins.active_plugins.get(plugin_shortname, None)
    if binsync_plugin is not None:
        return binsync_plugin

    main.workspace.plugins.activate_plugin_by_name(plugin_shortname)
    binsync_plugin = main.workspace.plugins.active_plugins.get(plugin_shortname, None)
    assert binsync_plugin is not None

    return binsync_plugin


def configure_and_connect(qtbot: QtBot, binsync_plugin, sync_dir_path, username, init=False):
    config = ConfigureBSDialog(binsync_plugin.controller, open_magic_sync=False, load_config=False)
    config.connect_client_to_project(username, sync_dir_path, initialize=init)

    # TODO: reinstate GUI testing of the config dialog in another test
    #qtbot.addWidget(config)
    #config._user_edit.setText("")
    #config._repo_edit.setText("")
    #qtbot.keyClicks(config._user_edit, username)
    #qtbot.keyClicks(config._repo_edit, sync_dir_path)
    #if init:
    #    qtbot.mouseClick(config._initrepo_checkbox, Qt.MouseButton.LeftButton)
    #qtbot.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)

    assert binsync_plugin.controller.status() == SyncControlStatus.CONNECTED_NO_REMOTE
    assert binsync_plugin.controller.client.master_user == username

def click_sync_menu(qtbot: QtBot, table, obj_name):
    """
    Syncs from the first entry in a context menu for a given table and menu object name
    """
    table.contextMenuEvent(QContextMenuEvent(QContextMenuEvent.Mouse, QPoint(-1, -1)))
    context_menu = next(
        filter(lambda x: isinstance(x, QMenu) and x.objectName() == obj_name,
               QApplication.topLevelWidgets()))

    # triple check we got the right menu
    assert (context_menu.objectName() == obj_name)
    sync_action = next(filter(lambda x: "Sync" == x.text(), context_menu.actions()))
    sync_action.trigger()
    context_menu.close()


def rename_function(qtbot: QtBot, main, func, new_func_name):
    disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
    disasm_view._t_flow_graph_visible = True
    disasm_view.display_function(func)
    disasm_view.decompile_current_function()
    main.workspace.main_instance.join_all_jobs()

    pseudocode_view = main.workspace._get_or_create_view("pseudocode", CodeView)
    for _, item in pseudocode_view.codegen.map_pos_to_node.items():
        if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CFunction):
            func_node = item.obj
            break
    else:
        raise Exception("The CFunction _instance is not found.")
    rnode = RenameNode(code_view=pseudocode_view, node=func_node)
    qtbot.addWidget(rnode)
    rnode._name_box.setText("")
    qtbot.keyClicks(rnode._name_box, new_func_name)
    qtbot.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)
    assert func.name == new_func_name


def rename_stack_variable(qtbot:QtBot, main, func, new_var_name, var_offset):
    disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
    disasm_view._t_flow_graph_visible = True
    disasm_view.display_function(func)
    disasm_view.decompile_current_function()
    main.workspace.main_instance.join_all_jobs()
    pseudocode_view = main.workspace._get_or_create_view("pseudocode", CodeView)
    for _, item in pseudocode_view.codegen.map_pos_to_node.items():
        if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CVariable) and \
                isinstance(item.obj.variable, angr.sim_variable.SimStackVariable) and \
                item.obj.variable.offset == var_offset:
            var_node = item.obj
            break
    else:
        raise Exception("The CFunction _instance is not found.")

    rnode = RenameNode(code_view=pseudocode_view, node=var_node, func=func)
    rnode._name_box.setText("")
    qtbot.keyClicks(rnode._name_box, new_var_name)
    qtbot.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

def get_stack_variable(main, func, var_offset, var_man=None):
    """
    Gets a stack variable from a given function and offset
    """
    if var_man is None:
        var_man = main.workspace.main_instance.pseudocode_variable_kb.variables.get_function_manager(func.addr)
    for var in var_man._unified_variables:
        if isinstance(var, angr.sim_variable.SimStackVariable) and var.offset == var_offset:
            renamed_var = var
            break
    else:
        return None
    return renamed_var

class TestBinsyncGUI(object):
    app = None

    @pytest.fixture(autouse=True)
    def run_around_tests(self):
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication([])
        yield
        try:
            self.app
        except:
            pass
        else:
            self.app.shutdown()

    def test_function_rename(self, qtbot: QtBot):
        print("\n")  # passing/failing doesn't add a newline sometimes

        binpath = os.path.join(test_location, "fauxware")
        new_function_name = "leet_main"
        user_1 = "user_1"
        user_2 = "user_2"
        print(f"Running function renaming test with users: {user_1} and {user_2}, func name: {new_function_name}")
        with tempfile.TemporaryDirectory() as sync_dir_path:
            print(f"Generating new directory: {sync_dir_path}")
            print("========= USER 1 =========")
            print("Starting angr-management gui..")
            assert QtWidgets.QApplication.instance() is not None
            print(self.app)
            main = start_am_gui(binpath, self.app)

            print("Grabbing main function..")
            func = main.workspace.main_instance.project.kb.functions['main']
            assert func is not None

            print("Grabbing binsync plugin..")
            binsync_plugin = get_binsync_am_plugin(main)

            print(f"Initializing/connecting to the repo in {sync_dir_path}")
            configure_and_connect(qtbot, binsync_plugin, sync_dir_path, user_1, True)

            print(f"Renaming function '{func.name}' to '{new_function_name}'")
            rename_function(qtbot, main, func, new_function_name)

            print("Blocking waiting for table updates..")
            control_panel = binsync_plugin.control_panel_view.control_panel
            for i in range(40):
                qWait(BINSYNC_RELOAD_TIME // 10, main.app)
                print(f"\tAttempt number {i + 1}/40..")
                try:
                    assert len(control_panel._func_table.table.model.row_data) == 1
                    top_change_func = control_panel._func_table.table.model.row_data[0]
                    assert len(control_panel._activity_table.table.model.row_data) == 1
                    top_change_activity = control_panel._activity_table.table.model.row_data[0]
                    assert top_change_func[3] != -1
                    break
                except AssertionError:
                    continue
            else:
                raise Exception("Repo updates never made it to table!")

            print("Checking data for correctness..")
            assert top_change_func[0] == top_change_activity[1]
            assert top_change_func[1] == new_function_name
            assert top_change_func[2] == top_change_activity[0]
            assert top_change_func[3] is not None

            print("Exiting first angr-management instance..")
            binsync_plugin.controller.stop_worker_routines()
            qWait(1000, main.app)  # sleep 1s

            main.close()
            os.remove(sync_dir_path + "/.git/binsync.lock")

            print("========= USER 2 =========")

            print("Starting angr-management gui..")
            main = start_am_gui(binpath, self.app)

            print("Grabbing main function..")
            func = main.workspace.main_instance.project.kb.functions['main']
            assert func is not None

            print("Grabbing binsync plugin..")
            binsync_plugin = get_binsync_am_plugin(main)

            print(f"Initializing/connecting to the repo in {sync_dir_path}")
            configure_and_connect(qtbot, binsync_plugin, sync_dir_path, user_2, init=False)

            print("Blocking waiting for table updates..")
            control_panel = binsync_plugin.control_panel_view.control_panel
            for i in range(40):
                qWait(BINSYNC_RELOAD_TIME // 10, main.app)
                print(f"\tAttempt number {i + 1}/40..")
                try:
                    assert len(control_panel._func_table.table.model.row_data) == 1
                    assert control_panel._func_table.table.model.row_data[0][3] != -1
                    break
                except AssertionError:
                    continue
            else:
                raise Exception("Repo updates never made it to table!")

            print("Syncing..")
            click_sync_menu(qtbot, control_panel._func_table.table, "binsync_function_table_context_menu")

            print("Checking sync for correctness..")
            for i in range(3):
                try:
                    assert func.name == new_function_name
                    break
                except AssertionError:
                    pass
                qWait(1000, main.app)
            else:
                raise Exception("Sync failed!")

            print("Exiting second client..")
            binsync_plugin.controller.stop_worker_routines()
            qWait(1000, main.app)

            main.close()

    def test_stack_variable_rename(self, qtbot: QtBot):
        print("\n")  # passing/failing doesn't add a newline sometimes

        binpath = os.path.join(test_location, "fauxware")
        var_offset = -0x18
        new_var_name = "leet_buff"
        user_1 = "user_1"
        user_2 = "user_2"

        print(f"Running stack variable renaming test with users: {user_1} and {user_2}, var name: {new_var_name}")
        with tempfile.TemporaryDirectory() as sync_dir_path:
            print(f"Generating new directory: {sync_dir_path}")
            print("========= USER 1 =========")
            print("Starting angr-management gui..")
            main = start_am_gui(binpath, self.app)

            print("Grabbing main function..")
            func = main.workspace.main_instance.project.kb.functions['main']
            assert func is not None
            old_name = func.name

            print("Grabbing binsync plugin..")
            binsync_plugin = get_binsync_am_plugin(main)

            print(f"Initializing/connecting to the repo in {sync_dir_path}")
            configure_and_connect(qtbot, binsync_plugin, sync_dir_path, user_1, True)

            print(f"Renaming variable to '{new_var_name}'")
            rename_stack_variable(qtbot, main, func, new_var_name, var_offset)

            print("Blocking waiting for table updates..")
            control_panel = binsync_plugin.control_panel_view.control_panel
            for i in range(40):
                qWait(BINSYNC_RELOAD_TIME // 10, main.app)
                print(f"\tAttempt number {i + 1}/40..")
                try:
                    assert len(control_panel._func_table.table.model.row_data) == 1
                    top_change_func = control_panel._func_table.table.model.row_data[0]
                    assert top_change_func[3] != -1
                    break
                except AssertionError:
                    continue
            else:
                raise Exception("Repo updates never made it to table!")

            print("Checking data for correctness..")
            top_func_addr_lowered = control_panel.controller.deci.art_lifter.lower_addr(top_change_func[0])
            assert top_func_addr_lowered == func.addr
            assert top_change_func[1] == ""
            assert top_change_func[2] == user_1
            assert top_change_func[3] is not None

            # check for var correctness
            var_man = main.workspace.main_instance.pseudocode_variable_kb.variables.get_function_manager(func.addr)
            assert get_stack_variable(main, func, var_offset, var_man).name == new_var_name

            print("Exiting first angr-management instance..")
            binsync_plugin.controller.stop_worker_routines()
            qWait(1000, main.app)  # sleep 1s

            main.close()
            os.remove(sync_dir_path + "/.git/binsync.lock")

            print("========= USER 2 =========")

            print("Starting angr-management gui..")
            main = start_am_gui(binpath, self.app)

            print("Grabbing main function..")
            func = main.workspace.main_instance.project.kb.functions['main']
            assert func is not None

            print("Grabbing binsync plugin..")
            binsync_plugin = get_binsync_am_plugin(main)

            print(f"Initializing/connecting to the repo in {sync_dir_path}")
            configure_and_connect(qtbot, binsync_plugin, sync_dir_path, user_2, init=False)

            print("Blocking waiting for table updates..")
            control_panel = binsync_plugin.control_panel_view.control_panel
            for i in range(40):
                qWait(BINSYNC_RELOAD_TIME // 10, main.app)
                print(f"\tAttempt number {i + 1}/40..")
                try:
                    assert len(control_panel._func_table.table.model.row_data) == 1
                    top_change_func = control_panel._func_table.table.model.row_data[0]
                    assert top_change_func[3] != -1
                    break
                except AssertionError:
                    continue
            else:
                raise Exception("Repo updates never made it to table!")

            top_func_addr_lowered = control_panel.controller.deci.art_lifter.lower_addr(top_change_func[0])
            assert top_func_addr_lowered == func.addr
            assert top_change_func[1] == ""
            assert top_change_func[2] == user_1
            assert top_change_func[3] is not None

            print("Syncing..")
            click_sync_menu(qtbot, control_panel._func_table.table, "binsync_function_table_context_menu")

            print("Checking sync for correctness..")
            for i in range(3):
                try:
                    assert func.name == old_name
                    stkvar = get_stack_variable(main, func, var_offset, var_man)
                    assert stkvar is not None
                    assert stkvar.name == new_var_name
                    break
                except AssertionError:
                    pass
                qWait(1000, main.app)
            else:
                raise Exception("Sync failed!")

            print("Exiting second client..")
            binsync_plugin.controller.stop_worker_routines()
            qWait(1000, main.app)

            main.close()

if __name__ == "__main__":
    pytest.main(args=sys.argv)