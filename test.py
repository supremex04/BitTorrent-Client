import socket

SERVER =  socket.gethostbyname(socket.gethostname())
PORT = 5050
ADDR = (SERVER, PORT)
print(SERVER)
print(socket.gethostname())

server =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


