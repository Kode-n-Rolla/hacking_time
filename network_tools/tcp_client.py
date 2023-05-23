# Musthave module to fast creation clients and servers
import socket

target_host = '0.0.0.0'  # Your target host
target_port = 9998    # Your target port

# Create socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET - IPv4, SOCK_STREAM - TCP

# Connect client
client.connect((target_host, target_port))

# Send some data
client.send(b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n')

# Receive some data
response = client.recv(4096)

print(f'Output - {response.decode()}')

# Close the connection
client.close()
