#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import select
from app import HTTPServer


IP = ""
PORT = 8080
FILES_DIR = "www"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((IP, PORT))
server.listen(5)
server.setblocking(0)
app = HTTPServer(FILES_DIR)

print("Server Running at http://{}:{}\n".format(IP if IP else "127.0.0.1", PORT))

clients = []
reqs = {}
responses = {}



while True:
    # Call select to ask the OS to check given sockets whether they are ready to write, read, or if
    # there is some exception respectively.
    # It passes three lists of sockets to specify which socket is expected to be writable, readable,
    # and which should be checked for errors
    readable, writable, exceptions = select.select(clients + [server], clients, [])
    for client in readable:
        if client == server:
            client, addr = server.accept()
            client.setblocking(0)
            clients.append(client)
            reqs[client] = b''
            print("\nNew client connected.", addr)
        else:
            reqs[client] += client.recv(1500)
            req = reqs[client]
            print("Request from", client.getpeername())
            responses[client] = app.request(req)
            del reqs[client]

    for client in writable:
        if client in responses.keys():
            print("Response to", client.getpeername())
            # print(header.decode())
            sent = client.send(responses[client])
            print("Sent", sent, "bytes")
            if sent < len(responses[client]):
                responses[client] = responses[client][sent:]
            else:
                print("Connection Closed", client.getpeername())
                client.close()
                del responses[client]
                clients.remove(client)
