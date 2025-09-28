from flask import Flask

app = Flask(__name__)

@app.route('/')
def handle_connection():
    return 'Hello World'

# main driver function
def start_server(port=7962):
    print("starting server!")
    app.run("::",port)
    print("stopping server!")
    