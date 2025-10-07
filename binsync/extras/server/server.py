from flask import Flask
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

# main driver function
def start_server(port=7962):
    l.info("starting server!")
    app.run("::",port)
    l.info("stopping server!")