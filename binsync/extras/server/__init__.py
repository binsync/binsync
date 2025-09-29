from flask import Flask
from threading import Lock
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
    print("starting server!")
    app.run("::",port)
    print("stopping server!")
    