import socket
def start_server(port=7962):
    print("Starting BinSync server...")
    print("WARNING - ONLY SUPPORTS ONE SINGLE CONNECTION CURRENTLY")
    server_socket = socket.socket(socket.AF_INET6,socket.SOCK_STREAM) # Can assume that all users will have devices that support ipv6?
    server_socket.bind(("0:0:0:0:0:0:0:0",port))
    server_socket.listen()
    print("Listening to",server_socket.getsockname())
    conn, addr = server_socket.accept()
    while True:
        comm = conn.recv(1024)
        conn.send(b'Received '+comm)
    # How to implement server cleanup?