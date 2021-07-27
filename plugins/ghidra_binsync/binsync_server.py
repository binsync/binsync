from flask import Flask, flash, request, redirect, jsonify
from flask_restful import Api, Resource, reqparse
import binsync

parser = reqparse.RequestParser()
parser.add_argument('user', help='Rate to charge for this resource')
app = Flask(__name__)
api = Api(app)

repo_path = "/Users/mahaloz/binsync/sync_test"
master_user = "headless_0"
binary_hash = ""
sync_client = binsync.Client(master_user, repo_path, binary_hash)


class ReturnMsg:
    BAD_ARGS = "There were not enough args in this request"
    NO_SYNC_REPO = "Not connected to a sync repo"
    CONNECTED_NO_USER = "Connected, but not initialized to a user yet"
    CONNECTED = "Connected: "
    PULL_SUCCESS = "Successfully pulled: "


class SyncStatus(Resource):
    def get(self):
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO
        elif sync_client.state is None:
            return ReturnMsg.CONNECTED_NO_USER

        curr_user = sync_client.state.user
        funcs = sync_client.state.functions
        return ReturnMsg.CONNECTED + curr_user + str(funcs)


class PullRequest(Resource):
    def post(self):
        args = parser.parse_args()
        if not sync_client:
            return ReturnMsg.NO_SYNC_REPO
        elif 'user' not in args:
            return ReturnMsg.BAD_ARGS

        chosen_user = args['user']
        sync_client.change_active_state(chosen_user)

        return ReturnMsg.PULL_SUCCESS + chosen_user


api.add_resource(PullRequest, '/pull')
api.add_resource(SyncStatus, '/status')

if __name__ == '__main__':
    app.run(threaded=False)
    sync_client.change_active_state(sync_client.master_user)
    del sync_client
