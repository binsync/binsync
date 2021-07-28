import os
import sys

from flask import Flask, flash, request, redirect, jsonify
from flask_restful import Api, Resource, reqparse

import binsync

parser = reqparse.RequestParser()
parser.add_argument('user', help='Rate to charge for this resource')
app = Flask(__name__)
api = Api(app)

sync_client = None


class ReturnMsg:
    BAD_ARGS = "There were not enough args in this request"
    NO_SYNC_REPO = "Not connected to a sync repo"
    CONNECTED_NO_USER = "Connected, but not initialized to a user yet"
    CONNECTED = "Connected: "
    PULL_SUCCESS = "Successfully pulled: "
    SERVER_STOPPED = "Server Stopped"


class SyncStatus(Resource):
    def get(self):
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO
        elif sync_client.state is None:
            return ReturnMsg.CONNECTED_NO_USER

        curr_user = sync_client.state.user
        funcs = sync_client.state.functions
        return ReturnMsg.CONNECTED + curr_user


class Users(Resource):
    def get(self):
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO

        user_list = [u.name for u in sync_client.users()]
        users = ",".join(user_list)
        return users


class StopServer(Resource):
    def get(self):
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO

        del sync_client
        return ReturnMsg.SERVER_STOPPED


class PullRequest(Resource):
    def post(self):
        args = parser.parse_args()
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO
        elif 'user' not in args:
            return ReturnMsg.BAD_ARGS

        chosen_user = args['user']
        if chosen_user is None:
            return ReturnMsg.BAD_ARGS

        sync_client.change_active_state(chosen_user)

        return ReturnMsg.PULL_SUCCESS + chosen_user


api.add_resource(PullRequest, '/pull')
api.add_resource(SyncStatus, '/status')
api.add_resource(Users, '/users')
api.add_resource(StopServer, '/stop')

#
#   ================================= Main Code =================================
#


if len(sys.argv) < 3:
    print("Not enough args: Usage: ./binsync_server <master_user_name> <sync_repo_path>")
    sys.exit(0)

master_user = sys.argv[1]
repo_path = sys.argv[2]
binary_hash = ""

# start the binsync client
try:
    os.remove(repo_path + "/.git/binsync.lock")
except FileNotFoundError:
    pass
sync_client = binsync.Client(master_user, repo_path, binary_hash)
sync_client.start_auto()

app.run(threaded=False)
