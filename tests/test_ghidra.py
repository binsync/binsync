import io
import subprocess
import sys
from types import SimpleNamespace

import pytest

import binsync.interface_overrides.ghidra as ghidra_module
from binsync.interface_overrides.ghidra import ControlPanelWindow, GhidraRemoteInterfaceWrapper


class MockProcess:
    def __init__(self, returncode=None, timeout_on_first_wait=False):
        self.pid = 1234
        self.stderr = io.StringIO("")
        self.terminated = False
        self.killed = False
        self.waited = False
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_timeouts = []
        self._returncode = returncode
        self._timeout_on_first_wait = timeout_on_first_wait

    def poll(self):
        return self._returncode

    def terminate(self):
        self.terminated = True
        self.terminate_calls += 1

    def wait(self, timeout=None):
        self.waited = True
        self.wait_timeouts.append(timeout)
        if self._timeout_on_first_wait and len(self.wait_timeouts) == 1:
            raise subprocess.TimeoutExpired("ghidra-ui", timeout)
        self._returncode = 0

    def kill(self):
        self.killed = True
        self.kill_calls += 1
        self._returncode = -9


class MockServer:
    def __init__(self):
        self.socket_path = "/tmp/fake-ghidra.sock"
        self.started = False
        self.stopped = False
        self.stop_calls = 0
        self.waited = False
        self.requires_main_thread = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True
        self.stop_calls += 1

    def wait_for_shutdown(self):
        self.waited = True


def _patch_popen_capture(monkeypatch, mock_proc):
    """Patch subprocess.Popen to capture call args/kwargs and return mock_proc."""
    popen_calls = []

    def mock_popen(*args, **kwargs):
        popen_calls.append((args, kwargs))
        return mock_proc

    monkeypatch.setattr("binsync.interface_overrides.ghidra.subprocess.Popen", mock_popen)
    return popen_calls


class DummyChangeManager:
    DOCR_EOL_COMMENT_CHANGED = 1
    DOCR_PRE_COMMENT_CHANGED = 2
    DOCR_POST_COMMENT_CHANGED = 3
    DOCR_PLATE_COMMENT_CHANGED = 4
    DOCR_REPEATABLE_COMMENT_CHANGED = 5

class DummyProgramChangeRecord:
    pass

class TestGhidra:
    """Tests for the Ghidra remote interface wrapper and UI process lifecycle.

    Note: a plain class is used instead of unittest.TestCase because pytest
    parameterization does not work on TestCase methods and results in cleaner tests.

    This file covers GhidraRemoteInterfaceWrapper (launching/retrying the out-of-process
    Ghidra UI, discovering the DecompilerClient/server URL, and tearing the UI process and
    server down) and ControlPanelWindow.closeEvent's shutdown ordering. Headless BSController
    behavior belongs in test_controller.py, Binary Ninja interface-override behavior in
    test_binja.py, and decompiler-agnostic Qt panel shutdown / table context-menu dispatch in
    test_ui_panels.py.
    """

    @pytest.mark.parametrize(
        "socket_path",
        [None, "/tmp/declib.sock"],
        ids=("default-server", "explicit-server"),
    )
    def test_launch_server_url(self, monkeypatch, tmp_path, socket_path):
        """GhidraRemoteInterfaceWrapper.start_gui_in_new_process must only inject
        BINSYNC_GHIDRA_SERVER_URL into the child process env when a socket_path is given, so the
        launched UI process picks up an explicit server address without the default-discovery
        path being disturbed. Cases cover the default server (no socket_path) and an explicit
        socket_path.
        """
        mock_proc = MockProcess()
        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_SERVER_URL, raising=False)
        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_UI_LOG_PATH, raising=False)
        monkeypatch.setattr(ghidra_module.tempfile, "gettempdir", lambda: str(tmp_path))
        monkeypatch.setattr("binsync.interface_overrides.ghidra.sleep", lambda _seconds: None)
        popen_calls = _patch_popen_capture(monkeypatch, mock_proc)

        proc = GhidraRemoteInterfaceWrapper.start_gui_in_new_process(socket_path=socket_path)

        assert proc is mock_proc
        launch_env = popen_calls[0][1]["env"]
        if socket_path is None:
            assert ghidra_module.BINSYNC_GHIDRA_SERVER_URL not in launch_env
        else:
            assert launch_env[ghidra_module.BINSYNC_GHIDRA_SERVER_URL] == f"unix://{socket_path}"

    @pytest.mark.parametrize(
        "explicit_log_path",
        [False, True],
        ids=("default-log-path", "explicit-log-path"),
    )
    def test_launch_log_path(self, monkeypatch, tmp_path, explicit_log_path):
        """GhidraRemoteInterfaceWrapper.start_gui_in_new_process must resolve the UI log file
        path from BINSYNC_GHIDRA_UI_LOG_PATH when set, otherwise fall back to a default path in
        the system temp directory, and redirect both stdout and stderr of the launched process to
        that same log file. Cases cover the default log path and an explicit log path.
        """
        mock_proc = MockProcess()
        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_SERVER_URL, raising=False)
        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_UI_LOG_PATH, raising=False)
        monkeypatch.setattr(ghidra_module.tempfile, "gettempdir", lambda: str(tmp_path))
        monkeypatch.setattr("binsync.interface_overrides.ghidra.sleep", lambda _seconds: None)

        if explicit_log_path:
            expected_log_path = tmp_path / "ghidra-ui.log"
            monkeypatch.setenv(ghidra_module.BINSYNC_GHIDRA_UI_LOG_PATH, str(expected_log_path))
        else:
            expected_log_path = tmp_path / "binsync-ghidra-ui.log"

        popen_calls = _patch_popen_capture(monkeypatch, mock_proc)

        proc = GhidraRemoteInterfaceWrapper.start_gui_in_new_process(socket_path=None)

        assert proc is mock_proc
        launch_kwargs = popen_calls[0][1]
        assert launch_kwargs["env"][ghidra_module.BINSYNC_GHIDRA_UI_LOG_PATH] == str(expected_log_path)
        assert launch_kwargs["stdout"].name == str(expected_log_path)
        assert launch_kwargs["stderr"] is launch_kwargs["stdout"]

    @pytest.mark.parametrize(
        "server_url",
        [None, "unix:///tmp/declib.sock"],
        ids=("discover-default-server", "discover-explicit-server"),
    )
    def test_ui_discovers_server_url(self, monkeypatch, server_url):
        """start_ghidra_ui must call DecompilerClient.discover with the server_url read from
        BINSYNC_GHIDRA_SERVER_URL when set, and with no server_url kwarg when the env var is
        unset, so the UI connects to the correct backend server on startup. Cases cover the
        default (env var unset) and an explicit server URL.
        """
        discover_calls = []
        mock_deci = object()

        class MockDecompilerClient:
            @staticmethod
            def discover(*args, **kwargs):
                discover_calls.append((args, kwargs))
                return mock_deci

        class MockApplication:
            @staticmethod
            def instance():
                return MockApplication()

            def setQuitOnLastWindowClosed(self, _value):
                pass

            def exec(self):
                pass

        class MockControlPanelWindow:
            def __init__(self, deci=None):
                self.deci = deci

            def hide(self):
                pass

            def configure(self):
                return True

            def show(self):
                pass

        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_SERVER_URL, raising=False)
        if server_url is not None:
            monkeypatch.setenv(ghidra_module.BINSYNC_GHIDRA_SERVER_URL, server_url)
        monkeypatch.setattr("declib.api.decompiler_client.DecompilerClient", MockDecompilerClient)
        monkeypatch.setattr(ghidra_module, "QApplication", MockApplication)
        monkeypatch.setattr(ghidra_module, "ControlPanelWindow", MockControlPanelWindow)

        ghidra_module.start_ghidra_ui()

        expected_kwargs = {"server_url": server_url} if server_url is not None else {}
        assert discover_calls == [((), expected_kwargs)]

    @pytest.mark.parametrize(
        ("returncode", "timeout_on_first_wait", "expected_terminate_calls", "expected_waits", "expected_kill_calls"),
        [
            (None, False, 1, [3], 0),
            (None, True, 1, [3, 1], 1),
            (0, False, 0, [], 0),
        ],
        ids=("normal-process", "timeout-and-kill", "already-exited-process"),
    )
    def test_wrapper_shutdown(
        self, returncode, timeout_on_first_wait, expected_terminate_calls, expected_waits, expected_kill_calls
    ):
        """GhidraRemoteInterfaceWrapper.shutdown must terminate the UI process only if it is
        still running, escalate to kill() if it does not exit within the wait timeout, always
        stop the server exactly once, and be idempotent when called twice, so a stuck or already
        exited Ghidra UI process never leaks or blocks shutdown. Cases cover a normal running
        process, a process that times out on terminate and must be killed, and a process that has
        already exited before shutdown is called.
        """
        mock_proc = MockProcess(returncode=returncode, timeout_on_first_wait=timeout_on_first_wait)
        mock_server = MockServer()
        wrapper = GhidraRemoteInterfaceWrapper.__new__(GhidraRemoteInterfaceWrapper)
        wrapper.gui_process = mock_proc
        wrapper.server = mock_server

        wrapper.shutdown()
        wrapper.shutdown()

        assert mock_proc.terminate_calls == expected_terminate_calls
        assert mock_proc.wait_timeouts == expected_waits
        assert mock_proc.kill_calls == expected_kill_calls
        assert mock_server.stopped is True
        assert mock_server.stop_calls == 1

    @pytest.mark.parametrize("requires_main_thread", [True, False], ids=("main-thread", "background-thread"))
    def test_wrapper_main_thread_wait(self, monkeypatch, requires_main_thread):
        """GhidraRemoteInterfaceWrapper.__init__ must start the DecompilerServer and launch the
        UI process, and must block on server.wait_for_shutdown only when the server reports it
        requires the main thread, so servers needing the main event loop do not return control
        prematurely while background-thread servers do not block construction. Cases cover a
        server that requires the main thread and one that does not.
        """
        mock_proc = MockProcess()
        mock_server = MockServer()
        mock_server.requires_main_thread = requires_main_thread
        monkeypatch.setattr("binsync.interface_overrides.ghidra.sleep", lambda _seconds: None)
        monkeypatch.setattr("binsync.interface_overrides.ghidra.DecompilerServer", lambda **_kwargs: mock_server)
        monkeypatch.setattr("binsync.interface_overrides.ghidra.atexit.register", lambda _callback: None)
        monkeypatch.setattr(
            GhidraRemoteInterfaceWrapper,
            "start_gui_in_new_process",
            staticmethod(lambda socket_path=None: mock_proc),
        )

        wrapper = GhidraRemoteInterfaceWrapper()

        assert wrapper.gui_process is mock_proc
        assert mock_server.started is True
        assert mock_server.waited is requires_main_thread

    @pytest.mark.parametrize(
        ("shutdown_method", "expected_shutdown_call"),
        [("shutdown_server", "shutdown_server"), ("shutdown", "interface_shutdown")],
        ids=("modern-interface", "legacy-interface"),
    )
    def test_control_panel_close_shutdown(self, monkeypatch, shutdown_method, expected_shutdown_call):
        """ControlPanelWindow.closeEvent must stop the controller's worker routines, shut down
        the remote interface (using shutdown_server on modern interfaces or shutdown on legacy
        ones), and quit the QApplication, in that order, so closing the panel window always
        cleanly tears down background work before the interface and app exit. Cases cover a
        modern interface exposing shutdown_server and a legacy interface exposing only shutdown.
        """
        calls = []

        class MockController:
            def stop_worker_routines(self):
                calls.append("stop_workers")

            def shutdown(self):
                calls.append("controller_shutdown")

        monkeypatch.setattr("binsync.interface_overrides.ghidra.QTimer.singleShot", lambda _delay, callback: callback())
        monkeypatch.setattr("binsync.interface_overrides.ghidra.QApplication.quit", lambda: calls.append("quit"))

        remote_interface = SimpleNamespace()
        setattr(remote_interface, shutdown_method, lambda: calls.append(expected_shutdown_call))
        window = SimpleNamespace(controller=MockController(), _interface=remote_interface)

        ControlPanelWindow.closeEvent(window, object())

        assert calls == ["stop_workers", expected_shutdown_call, "quit"]

    @pytest.mark.parametrize("successful_attempt", [2, None], ids=("retry-succeeds", "exhausted"))
    def test_launch_retries_or_exhausts(self, monkeypatch, tmp_path, successful_attempt):
        """GhidraRemoteInterfaceWrapper.start_gui_in_new_process must retry launching the UI
        process through its fallback methods (starting with sys.executable, then the "binsync"
        entry point) when a launch attempt exits with a failure code, and must raise a
        RuntimeError once all methods are exhausted, so a flaky or misconfigured first launch
        method does not permanently prevent the UI from starting. Cases cover a retry that
        eventually succeeds and one where every method fails.
        """
        popen_calls = []
        processes = []
        monkeypatch.delenv(ghidra_module.BINSYNC_GHIDRA_UI_LOG_PATH, raising=False)
        monkeypatch.setattr(ghidra_module.tempfile, "gettempdir", lambda: str(tmp_path))
        monkeypatch.setattr(ghidra_module, "sleep", lambda _seconds: None)

        def mock_popen(*args, **kwargs):
            popen_calls.append((args, kwargs))
            attempt = len(popen_calls)
            proc = MockProcess(returncode=None if attempt == successful_attempt else 1)
            processes.append(proc)
            return proc

        monkeypatch.setattr(ghidra_module.subprocess, "Popen", mock_popen)

        if successful_attempt is None:
            with pytest.raises(RuntimeError, match="Exhausted all methods"):
                GhidraRemoteInterfaceWrapper.start_gui_in_new_process()
            assert len(popen_calls) == 3
        else:
            proc = GhidraRemoteInterfaceWrapper.start_gui_in_new_process()
            assert proc is processes[successful_attempt - 1]
            assert len(popen_calls) == successful_attempt

        assert popen_calls[0][0][0][0] == ghidra_module.sys.executable
        if len(popen_calls) > 1:
            assert popen_calls[1][0][0][0] == "binsync"

    @pytest.mark.parametrize(
        ("has_text", "expected_deleted"),
        [(True, False), (False, True)],
        ids=("comment-added", "comment-deleted"),
    )
    def test_ghidra_comment_hook_dispatch(self, monkeypatch, has_text, expected_deleted):
        """DataMonitor.do_change_handler must intercept comment change events from Ghidra
        (DOCR_EOL_COMMENT_CHANGED, DOCR_PRE_COMMENT_CHANGED, etc.), extract the affected address,
        query the decompiler interface for the updated comment, and notify the interface via
        deci.comment_changed with deleted=False when text exists or deleted=True when text is cleared.
        """
        import sys
        from unittest.mock import MagicMock

        class GhidraModuleLoader:
            def find_spec(self, fullname, path, target=None):
                if fullname.startswith(("ghidra", "docking", "java")):
                    from importlib.machinery import ModuleSpec
                    return ModuleSpec(fullname, self, is_package=True)
                return None

            def create_module(self, spec):
                mod = MagicMock()
                mod.__name__ = spec.name
                if spec.name == "ghidra.program.util":
                    mod.ProgramChangeRecord = DummyProgramChangeRecord
                    mod.ChangeManager = DummyChangeManager
                return mod

            def exec_module(self, module):
                pass

        loader = GhidraModuleLoader()
        monkeypatch.setattr(sys, "meta_path", [loader] + sys.meta_path)

        mock_jpype = MagicMock()
        mock_jpype.JImplements = lambda *a, **kw: (lambda cls: cls)
        mock_jpype.JOverride = lambda func: func
        monkeypatch.setitem(sys.modules, "jpype", mock_jpype)

        mock_imports = MagicMock()
        mock_imports.ChangeManager = DummyChangeManager
        mock_imports.ProgramChangeRecord = DummyProgramChangeRecord
        monkeypatch.setitem(sys.modules, "declib.decompilers.ghidra.compat.imports", mock_imports)

        from declib.artifacts import Comment
        from declib.decompilers.ghidra.hooks import DataMonitor

        comment_calls = []

        class MockDeci:
            def get_comment(self, addr):
                if has_text:
                    return Comment(addr=addr, comment="Test Ghidra comment", func_addr=0x400100)
                return None

            def get_closest_function(self, addr):
                return 0x400100

            def comment_changed(self, cmt, deleted=False):
                comment_calls.append((cmt, deleted))

            def error(self, msg):
                print("DECI ERROR:", msg)

        deci = MockDeci()
        monitor = DataMonitor.__new__(DataMonitor)
        monitor._deci = deci
        monitor.funcEvents = set()
        monitor.typeEvents = set()
        monitor.symDelEvents = set()
        monitor.symChgEvents = set()
        monitor.imageBaseEvents = set()
        monitor.commentEvents = {DummyChangeManager.DOCR_EOL_COMMENT_CHANGED}
        monitor.TrackedEvents = monitor.commentEvents

        class MockAddr:
            def getOffset(self):
                return 0x400108

        class MockRecord(DummyProgramChangeRecord):
            def getEventType(self):
                return DummyChangeManager.DOCR_EOL_COMMENT_CHANGED

            def getByteAddress(self):
                return MockAddr()

            def getObject(self):
                return None

            def getNewValue(self):
                return None

        event = [MockRecord()]
        monitor.do_change_handler(event)

        assert len(comment_calls) == 1
        cmt, deleted = comment_calls[0]
        assert cmt.addr == 0x400108
        assert deleted is expected_deleted
        if has_text:
            assert cmt.comment == "Test Ghidra comment"

    @pytest.mark.parametrize(
        ("auto_push_enabled", "is_deleted"),
        [(True, False), (False, False), (True, True)],
        ids=("auto-push-active", "auto-push-disabled", "auto-push-deletion"),
    )
    def test_ghidra_comment_auto_push_integration(self, monkeypatch, tmp_path, auto_push_enabled, is_deleted):
        """When a comment change event is received from Ghidra, BSController must update the
        client's master_state comments dictionary and respect auto_push_enabled on the client.
        """
        from collections import defaultdict
        from declib.artifacts import Comment, Function
        from binsync.controller import BSController
        from binsync.core.state import State

        class MockGhidraClientInterface:
            name = "ghidra"
            should_watch_artifacts = lambda self: True

            def __init__(self):
                self.artifact_change_callbacks = defaultdict(list)
                self.functions = {0x400100: Function(addr=0x400100, size=0x50)}
                self.comments = {}
                self.global_vars = {}
                self.enums = {}
                self.typedefs = {}
                self.structs = {}
                self.patches = {}
                self.segments = {}

            def get_func_size(self, addr):
                return 0x50

            def shutdown(self):
                pass

        deci = MockGhidraClientInterface()
        controller = BSController(decompiler_interface=deci, headless=True)

        master_state = State("test_user")
        master_state.set_function(Function(addr=0x400100, size=0x50))
        if is_deleted:
            master_state.set_comment(Comment(addr=0x400108, comment="Old comment", func_addr=0x400100))

        class MockClient:
            def __init__(self):
                self.master_state = master_state
                self.push_on_update = auto_push_enabled

            def last_push_ts(self):
                return None

        client = MockClient()
        controller.client = client

        if is_deleted:
            cmt = Comment(addr=0x400108, comment="", func_addr=0x400100)
            controller.commit_artifact(cmt, deleted=True)
            assert 0x400108 not in master_state.comments
        else:
            cmt = Comment(addr=0x400108, comment="New Ghidra comment", func_addr=0x400100)
            controller.commit_artifact(cmt, deleted=False)
            assert 0x400108 in master_state.comments
            assert master_state.comments[0x400108].comment == "New Ghidra comment"

        assert controller.auto_push_enabled == auto_push_enabled

    def test_ghidra_interface_comment_methods(self, monkeypatch):
        """GhidraDecompilerInterface comment methods (_get_comment, _set_comment, _del_comment,
        _comments) must correctly construct, update, delete, and enumerate comments across
        single or tagged slots and use Ghidra's comment address iterator for bulk retrieval.
        """
        import sys
        from unittest.mock import MagicMock

        class MockCodeUnitTypes:
            PLATE_COMMENT = 0
            PRE_COMMENT = 1
            EOL_COMMENT = 2
            POST_COMMENT = 3
            REPEATABLE_COMMENT = 4

        mock_imports = MagicMock()
        mock_imports.CodeUnit = MockCodeUnitTypes
        monkeypatch.setitem(sys.modules, "declib.decompilers.ghidra.compat.imports", mock_imports)

        class MockGAddr:
            def __init__(self, offset):
                self._offset = offset
            def getOffset(self):
                return self._offset

        class MockCodeUnit:
            def __init__(self, addr, comments_map):
                self._addr = MockGAddr(addr)
                self._comments = comments_map

            def getAddress(self):
                return self._addr

            def getComment(self, cmt_type):
                return self._comments.get(cmt_type, None)

        code_units = {
            0x400108: MockCodeUnit(0x400108, {0: "Plate comment text", 2: "EOL comment text"}),
            0x400120: MockCodeUnit(0x400120, {2: "Single EOL comment"}),
        }

        class MockListing:
            def getCodeUnitAt(self, gaddr):
                return code_units.get(gaddr.getOffset(), None)

            def getCommentAddressIterator(self, min_addr, max_addr, forward):
                return [MockGAddr(addr) for addr in code_units.keys()]

        class MockProgram:
            def getListing(self):
                return MockListing()
            def getMinAddress(self):
                return MockGAddr(0x400000)
            def getMaxAddress(self):
                return MockGAddr(0x500000)

        from declib.decompilers.ghidra.interface import GhidraDecompilerInterface

        class MockGhidraInterface(GhidraDecompilerInterface):
            currentProgram = MockProgram()

            def __init__(self):
                pass

            def _to_gaddr(self, addr):
                return MockGAddr(addr)

            def get_closest_function(self, addr):
                return 0x400100

        interface = MockGhidraInterface()

        cmt1 = interface._get_comment(0x400120)
        assert cmt1 is not None
        assert cmt1.addr == 0x400120
        assert cmt1.comment == "Single EOL comment"

        cmt2 = interface._get_comment(0x400108)
        assert cmt2 is not None
        assert "[PLATE] Plate comment text" in cmt2.comment
        assert "[EOL] EOL comment text" in cmt2.comment

        all_cmts = interface._comments()
        assert len(all_cmts) == 2
        assert 0x400108 in all_cmts
        assert 0x400120 in all_cmts


if __name__ == "__main__":
    pytest.main(args=sys.argv)
