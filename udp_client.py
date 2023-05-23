# Musthave module to fast creation clients and servers
import socket

target_host = '127.0.0.1'   # Your target host
target_port = 9997      # Your target port

# Create socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # AF_INET - IPv4, SOCK_DGRAM - UDP

# Send some data
client.sendto(b'Send UDP data', (target_host, target_port))

# Receive some data
data, address = client.recvfrom(4096)

print(data.decode())

# Close connection
client.close()