import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from PySide2.QtGui import QContextMenuEvent
from PySide2.QtTest import QTest
from PySide2.QtCore import Qt, QPoint, QTimer
from PySide2.QtWidgets import QApplication, QMenu

import angr
from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.main_window import MainWindow
from angrmanagement.config import Conf

from binsync.common.controller import SyncControlStatus, BINSYNC_RELOAD_TIME
from binsync.common.ui import utils
from binsync.common.ui import set_ui_version
set_ui_version("PySide2")
from binsync.common.ui.config_dialog import SyncConfig

app = None
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'binaries')


#
# Test Utilities
#

def config_and_connect(binsync_plugin, username, sync_dir_path):
    config = SyncConfig(binsync_plugin.controller)
    config._user_edit.setText("")
    config._repo_edit.setText("")
    QTest.keyClicks(config._user_edit, username)
    QTest.keyClicks(config._repo_edit, sync_dir_path)
    # always init for first user
    QTest.mouseClick(config._initrepo_checkbox, Qt.MouseButton.LeftButton)
    QTest.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)


def get_binsync_am_plugin(main_window):
    binsync_plugin = next(iter(
        [p for p in main_window.workspace.plugins.active_plugins if "BinSync" in str(p)]
    ))  # type: BinSyncPlugin
    return binsync_plugin


def start_am_gui(binpath):
    main = MainWindow(show=False)
    main.workspace.instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
    main.workspace.instance.project.am_event()
    main.workspace.instance.join_all_jobs()
    return main


def emulate_sync_menu_click(table, row_idx, sync_from=None):
    """
    Simulates a click on a row in any given table followed by another click for a context menu selection.
    This is so you can use both the "Sync" and "Sync From..." options.

    table: the table you want to sync from
    row_idx: the index of the row in the table you want to click (0 is the first row)
    sync_from: the optional user/function you want to sync from
    """

    def _menu_stub(menu):
        """
        This is a stub override function. Found in the utilities of BinSync common UI is a
        stub that wraps QMenu. It just returns QMenu back when normally called in the code. We
        override the stub so that we can also override the objects `exec_` method.

        We override the exec_ method to avoid a popup and to allow us to select a sync action
        from the menu that will popup.
        """
        def exec_(*args, **kwargs):
            # find the parent menu
            parent = kwargs.get("parent", None)
            if not parent:
                return None

            # sync from shown user
            if not sync_from:
                return [action for action in parent.actions() if action.text() == "Sync"][0]

            # sync from a selected user/function
            actions = [action for action in parent.actions() if action.text() != "Sync"][0]
            action = [act for act in actions if act.text() == sync_from][0]
            return action

        menu.exec_ = exec_
        return menu

    # create a real coordinate click point from the given target row idx
    click_point = QPoint(5, table.rowViewportPosition(row_idx))
    click_event = QContextMenuEvent(
        QContextMenuEvent.Reason.Mouse,
        click_point,  # QPoint(0 + PIXEL_OFFSET, 0 + PIXEL_OFFSET)
    )

    # only temporarily override the menu_stub
    with unittest.mock.patch.object(utils, "menu_stub", _menu_stub):
        table.contextMenuEvent(click_event)


def am_setUp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()


#
# Tests
#


class TestBinSyncPluginGUI(unittest.TestCase):
    """
    Unit Tests to test the BinSync Plugin for syncing across two users or more.
    Done inside angr-management.
    """

    def setUp(self):
        am_setUp()

    #
    # Tests
    #

    def test_function_rename(self):
        binpath = os.path.join(test_location, "fauxware")
        new_function_name = "leet_main"
        user_1 = "user_1"
        user_2 = "user_2"

        with tempfile.TemporaryDirectory() as sync_dir_path:
            # ========= USER 1 =========
            # setup GUI
            main = start_am_gui(binpath)
            func = main.workspace.instance.project.kb.functions['main']
            self.assertIsNotNone(func)

            # find the binsync plugin and connect
            binsync_plugin = get_binsync_am_plugin(main)
            config_and_connect(binsync_plugin, user_1, sync_dir_path)
            self.assertEqual(binsync_plugin.controller.status(), SyncControlStatus.CONNECTED_NO_REMOTE)
            self.assertEqual(binsync_plugin.controller.client.master_user, user_1)

            # trigger a function rename in decompilation
            disasm_view = main.workspace._get_or_create_disassembly_view()
            disasm_view._t_flow_graph_visible = True
            disasm_view.display_function(func)
            disasm_view.decompile_current_function()
            main.workspace.instance.join_all_jobs()
            pseudocode_view = main.workspace._get_or_create_pseudocode_view()
            for _, item in pseudocode_view.codegen.map_pos_to_node.items():
                if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CFunction):
                    func_node = item.obj
                    break
            else:
                self.fail("The CFunction _instance is not found.")
            rnode = RenameNode(code_view=pseudocode_view, node=func_node)
            rnode._name_box.setText("")
            QTest.keyClicks(rnode._name_box, new_function_name)
            QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)
            self.assertEqual(func.name, new_function_name)

            # assure a new commit makes it to the repo
            time.sleep(BINSYNC_RELOAD_TIME + BINSYNC_RELOAD_TIME//2)
            control_panel = binsync_plugin.control_panel_view.control_panel
            func_table = control_panel._func_table
            top_change = func_table.items[0]
            self.assertEqual(top_change.user, user_1)
            self.assertEqual(top_change.name, new_function_name)
            self.assertIsNot(top_change.last_push, None)

            # reset the repo
            os.remove(sync_dir_path + "/.git/binsync.lock")

            # ========= USER 2 =========
            # setup GUI
            main = start_am_gui(binpath)
            func = main.workspace.instance.project.kb.functions['main']
            self.assertIsNotNone(func)

            # find the binsync plugin and connect
            binsync_plugin = get_binsync_am_plugin(main)
            config_and_connect(binsync_plugin, user_2, sync_dir_path)
            self.assertEqual(binsync_plugin.controller.status(), SyncControlStatus.CONNECTED_NO_REMOTE)
            self.assertEqual(binsync_plugin.controller.client.master_user, user_2)

            # wait for the control panel to get new data and force UI reload
            time.sleep(BINSYNC_RELOAD_TIME)
            control_panel = binsync_plugin.control_panel_view.control_panel
            control_panel.reload()

            # make a click event to sync new data from the first row in the table
            func_table = control_panel._func_table
            emulate_sync_menu_click(func_table, 0)

            self.assertEqual(func.name, new_function_name)
            app.exit(0)

    def test_stack_variable_rename(self):
        binpath = os.path.join(test_location, "fauxware")
        var_offset = -0x18
        new_var_name = "leet_buff"
        user_1 = "user_1"
        user_2 = "user_2"

        with tempfile.TemporaryDirectory() as sync_dir_path:
            # ========= USER 1 =========
            # setup GUI
            main = start_am_gui(binpath)
            func = main.workspace.instance.project.kb.functions['main']
            old_name = func.name
            self.assertIsNotNone(func)

            # find the binsync plugin and connect
            binsync_plugin = get_binsync_am_plugin(main)
            config_and_connect(binsync_plugin, user_1, sync_dir_path)
            self.assertEqual(binsync_plugin.controller.status(), SyncControlStatus.CONNECTED_NO_REMOTE)
            self.assertEqual(binsync_plugin.controller.client.master_user, user_1)

            # trigger a variable rename in decompilation
            disasm_view = main.workspace._get_or_create_disassembly_view()
            disasm_view._t_flow_graph_visible = True
            disasm_view.display_function(func)
            disasm_view.decompile_current_function()
            main.workspace.instance.join_all_jobs()
            pseudocode_view = main.workspace._get_or_create_pseudocode_view()
            for _, item in pseudocode_view.codegen.map_pos_to_node.items():
                if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CVariable) and \
                        isinstance(item.obj.variable, angr.sim_variable.SimStackVariable) and \
                        item.obj.variable.offset == var_offset:
                    var_node = item.obj
                    break
            else:
                self.fail("The CVariable _instance is not found.")
            rnode = RenameNode(code_view=pseudocode_view, node=var_node)
            rnode._name_box.setText("")
            QTest.keyClicks(rnode._name_box, new_var_name)
            QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

            # find the variable in the var manager
            var_man = main.workspace.instance.pseudocode_variable_kb.variables.get_function_manager(func.addr)
            for var in var_man._unified_variables:
                if isinstance(var, angr.sim_variable.SimStackVariable) and var.offset == var_offset:
                    renamed_var = var
                    break
            else:
                self.fail("Renamed variable is not found")

            self.assertTrue(renamed_var.renamed)
            self.assertEqual(renamed_var.name, new_var_name)

            # assure a new commit makes it to the repo
            time.sleep(BINSYNC_RELOAD_TIME + BINSYNC_RELOAD_TIME//2)
            control_panel = binsync_plugin.control_panel_view.control_panel
            activity_table = control_panel._activity_table
            top_change = activity_table.items[0]
            self.assertEqual(top_change.user, user_1)
            self.assertEqual(top_change.activity, func.addr)
            self.assertIsNot(top_change.last_push, None)

            # reset the repo
            os.remove(sync_dir_path + "/.git/binsync.lock")

            # ========= USER 2 =========
            # setup GUI
            main = start_am_gui(binpath)
            func = main.workspace.instance.project.kb.functions['main']
            self.assertIsNotNone(func)

            # find the binsync plugin and connect
            binsync_plugin = get_binsync_am_plugin(main)
            config_and_connect(binsync_plugin, user_2, sync_dir_path)
            self.assertEqual(binsync_plugin.controller.status(), SyncControlStatus.CONNECTED_NO_REMOTE)
            self.assertEqual(binsync_plugin.controller.client.master_user, user_2)

            # wait for the control panel to get new data and force UI reload
            time.sleep(BINSYNC_RELOAD_TIME)
            control_panel = binsync_plugin.control_panel_view.control_panel
            control_panel.reload()

            # assure functions did not change
            func_table = control_panel._func_table
            self.assertIsNotNone(func_table.items[0].name)

            # make a click event to sync new data from the first row in the table
            activity_table = control_panel._activity_table
            emulate_sync_menu_click(activity_table, 0)

            # assure function name did not change
            self.assertEqual(func_table.items[0].name, "")
            self.assertEqual(func.name, old_name)

            for var in var_man._unified_variables:
                if isinstance(var, angr.sim_variable.SimStackVariable) and var.offset == var_offset:
                    renamed_var = var
                    break
            else:
                self.fail("Renamed variable is not found")

            self.assertTrue(renamed_var.renamed)
            self.assertEqual(renamed_var.name, new_var_name)

            app.exit(0)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
