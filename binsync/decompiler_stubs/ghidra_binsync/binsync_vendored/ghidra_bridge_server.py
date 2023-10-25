import logging
import subprocess
import sys
from jfx_bridge import bridge
from ghidra_bridge_port import DEFAULT_SERVER_PORT

# NOTE: we definitely DON'T want to exclude ghidra from ghidra_bridge :P
import ghidra


class GhidraBridgeServer(object):
    """ Class mostly used to collect together functions and variables that we don't want contaminating the global namespace
        variables set in remote clients

        NOTE: this class needs to be excluded from ghidra_bridge - it doesn't need to be in the globals, if people want it and
        know what they're doing, they can get it from the BridgedObject for the main module
    """

    class PrintAccumulator(object):
        """ Class to handle capturing print output so we can send it across the bridge, by hooking sys.stdout.write().
            Not multithreading aware, it'll just capture whatever is printed from the moment it hooks to the moment 
            it stops.
        """

        output = None
        old_stdout = None

        def __init__(self):
            self.output = ""

        def write(self, output):
            self.output += output

        def get_output(self):
            return self.output

        def hook(self):
            self.old_stdout = sys.stdout
            sys.stdout = self

        def unhook(self):
            if self.old_stdout is not None:
                sys.stdout = self.old_stdout

        def __enter__(self):
            self.hook()

            return self

        def __exit__(self, type, value, traceback):
            self.unhook()

    @staticmethod
    def ghidra_help(param=None):
        """ call the ghidra help method, capturing the print output with PrintAccumulator, and return it as a string """
        with GhidraBridgeServer.PrintAccumulator() as help_output:
            help(param)

            return help_output.get_output()

    class InteractiveListener(ghidra.framework.model.ToolListener):
        """ Class to handle registering for plugin events associated with the GUI
            environment, and sending them back to clients running in interactive mode
            so they can update their variables 

            We define the interactive listener on the server end, so it can
            cleanly recover from bridge failures when trying to send messages back. If we
            let it propagate exceptions up into Ghidra, the GUI gets unhappy and can stop
            sending tool events out 
        """

        tool = None
        callback_fn = None

        def __init__(self, tool, callback_fn):
            """ Create with the tool to listen to (from state.getTool() - won't change during execution)
                and the callback function to notify on the client end (should be the update_vars function) """
            self.tool = tool
            self.callback_fn = callback_fn

            # register the listener against the remote tool
            tool.addToolListener(self)

        def stop_listening(self):
            # we're done, make sure we remove the tool listener
            self.tool.removeToolListener(self)

        def processToolEvent(self, plugin_event):
            """ Called by the ToolListener interface """
            try:
                self.callback_fn._bridge_conn.logger.debug(
                    "InteractiveListener got event: " + str(plugin_event)
                )

                event_name = plugin_event.getEventName()
                if "Location" in event_name:
                    self.callback_fn(
                        currentProgram=plugin_event.getProgram(),
                        currentLocation=plugin_event.getLocation(),
                    )
                elif "Selection" in event_name:
                    self.callback_fn(
                        currentProgram=plugin_event.getProgram(),
                        currentSelection=plugin_event.getSelection(),
                    )
                elif "Highlight" in event_name:
                    self.callback_fn(
                        currentProgram=plugin_event.getProgram(),
                        currentHighlight=plugin_event.getHighlight(),
                    )
            except Exception as e:
                # any exception, we just want to bail and shut down the listener.
                # most likely case is the bridge connection has gone down.
                self.stop_listening()
                self.callback_fn._bridge_conn.logger.error(
                    "InteractiveListener failed trying to callback client: " + str(e)
                )

    @staticmethod
    def run_server(
        server_host=bridge.DEFAULT_HOST,
        server_port=DEFAULT_SERVER_PORT,
        response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT,
        background=True,
    ):
        """ Run a ghidra_bridge_server (forever)
            server_host - what address the server should listen on
            server_port - what port the server should listen on
            response_timeout - default timeout in seconds before a response is treated as "failed"
            background - false to run the server in this thread (script popup will stay), true for a new thread (script popup disappears)
        """
        server = bridge.BridgeServer(
            server_host=server_host,
            server_port=server_port,
            loglevel=logging.INFO,
            response_timeout=response_timeout,
        )

        if background:
            server.start()
            server.logger.info(
                "Server launching in background - will continue to run after launch script finishes..."
            )
        else:
            server.run()

    @staticmethod
    def run_script_across_ghidra_bridge(script_file, python="python", argstring=""):
        """ Spin up a ghidra_bridge_server and spawn the script in external python to connect back to it. Useful in scripts being triggered from
            inside ghidra that need to use python3 or packages that don't work in jython

            The called script needs to handle the --connect_to_host and --connect_to_port command-line arguments and use them to start
            a ghidra_bridge client to talk back to the server.

            Specify python to control what the script gets run with. Defaults to whatever python is in the shell - if changing, specify a path
            or name the shell can find.
            Specify argstring to pass further arguments to the script when it starts up.
        """

        # spawn a ghidra bridge server - use server port 0 to pick a random port
        server = bridge.BridgeServer(
            server_host="127.0.0.1", server_port=0, loglevel=logging.INFO
        )
        # start it running in a background thread
        server.start()

        try:
            # work out where we're running the server
            server_host, server_port = server.server.bridge.get_server_info()

            print("Running " + script_file)

            # spawn an external python process to run against it

            try:
                output = subprocess.check_output(
                    "{python} {script} --connect_to_host={host} --connect_to_port={port} {argstring}".format(
                        python=python,
                        script=script_file,
                        host=server_host,
                        port=server_port,
                        argstring=argstring,
                    ),
                    stderr=subprocess.STDOUT,
                    shell=True,
                )
                print(output)
            except subprocess.CalledProcessError as exc:
                print("Failed ({}):{}".format(exc.returncode, exc.output))

            print(script_file + " completed")

        finally:
            # when we're done with the script, shut down the server
            server.shutdown()


if __name__ == "__main__":
    # legacy version - run the server in the foreground, so we don't break people's expectations
    GhidraBridgeServer.run_server(
        response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT, background=False
    )

