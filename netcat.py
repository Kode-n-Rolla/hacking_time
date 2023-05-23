import argparse     # To creation command line interface
import socket
import shlex
import subprocess   # To creat a process, which help to interact with clients programm
import sys
import textwrap
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return

    # check_out = execute command in local machine and return the output that of this command
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)

    return output.decode()

class NetCat:
    def __init__(self, args, buffer=None):   # Initialize NetCat object
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Create socket object
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        self.socket.connect((self.args.target, self.args.port)) # Connect to target machine
        if self.buffer:
            self.socket.send(self.buffer)
        try:
            while True:  # Loop for receive data from the target server
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:  # If mo more data, break loop
                        break
                if response:     # If there is a data:
                    print(f'Response - {response}')   # Output response
                    buffer = input('> ')   # Stop to get input
                    buffer += '\n'
                    self.socket.send(buffer.encode())    # Send it
        except KeyboardInterrupt:  # Ctrl+C - stop socket work
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port)) # Bind to target 
        self.socket.listen(5)
        
        # Start to listening
        while True:
            client_socket, _ = self.socket.accept()

            # Send sockets to handle method
            client_thread = threading.Thread(target=self.handle, args=(client_socket, ))
            client_thread.start()

    # Method handle execute command (exucute, upload, create shell)
    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saves file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'my_shell: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'Server killed {e}')
                    self.socket.close()
                    sys.exit()

# The main block, with responsible for arguments command line and calling other functions
if __name__ == '__main__':

    # Information about the programm
    parser = argparse.ArgumentParser(
        description = 'Net Tool',
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent('''Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # download to file
        netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # send text to server port 135
        netcat.py -t 192.168.1.108 -p 5555 # connect to server'''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()

    # If programm use as listener
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()

