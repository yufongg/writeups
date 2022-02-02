import sys
# 256 is FF, end of hex
for x in range(0,256):
	sys.stdout.write("\\x" + '{:02x}'.format(x))
