from flask import Flask, request
from threading import Lock
import logging

l = logging.getLogger(__name__)
app = Flask(__name__)

user_count_lock = Lock()
user_count = 0
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
    function_addr_received = request.form["address"]
    if function_addr_received:
        current_function_address = int(request.form["address"])
        l.info("Some user is at the function at address %x",current_function_address)
    else:
        l.info("A user made a post to function but the function address was not valid")
    return "OK"

# main driver function
def start_server(port=7962):
    l.info("starting server!")
    app.run("::",port)
    l.info("stopping server!")