from flask import Flask, request
from threading import Lock
import logging

l = logging.getLogger(__name__)
app = Flask(__name__)

user_count_lock = Lock()
user_count = 0
users:dict[str:any] = {}

@app.route('/connect')
def handle_connection():
    global user_count
    with user_count_lock:
        user_count += 1
        print(user_count)
    return 'You are connected!'

@app.route("/disconnect")
def handle_disconnection():
    global user_count
    with user_count_lock:
        user_count -= 1
        print(user_count)
    return 'You have disconnected!'

@app.route("/function",methods=["POST"])
def receive_function():
    global users
    if "username" in request.form: # Can't keep track of users if they are not associated with a username
        username = request.form["username"]
        user_info = {
            "addr":None,
            "func_addr":None
        }
        if "address" in request.form:
            user_info["addr"] = int(request.form["address"])
        if "function_address" in request.form:
            user_info["func_addr"] = int(request.form["function_address"])
        users[username] = user_info
    l.info(users)
    return "OK"

# main driver function
def start_server(port=7962):
    l.info("starting server!")
    app.run("::",port)
    l.info("stopping server!")