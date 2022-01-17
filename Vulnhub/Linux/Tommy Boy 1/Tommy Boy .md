# NMAP

* tcp/22
* tcp/80
* tcp/8008

## FFUF (tcp/80)

````
┌──(root💀kali)-[~/vulnHub/TommyBoy1]
└─# ffuf -u http://192.168.56.129/FUZZ -w /usr/share/wordlists/dirb/common.txt  -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.129/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 301
________________________________________________

.hta                    [Status: 403, Size: 293, Words: 22, Lines: 12]
                        [Status: 200, Size: 1176, Words: 164, Lines: 18]
.htaccess               [Status: 403, Size: 298, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 298, Words: 22, Lines: 12]
cgi-bin/                [Status: 200, Size: 745, Words: 52, Lines: 16]
index.html              [Status: 200, Size: 1176, Words: 164, Lines: 18]
robots.txt              [Status: 200, Size: 132, Words: 6, Lines: 6]
server-status           [Status: 403, Size: 302, Words: 22, Lines: 12]
:: Progress: [4614/4614] :: Job [1/1] :: 429 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

````

## FFUF (tcp/8008)

````
┌──(root💀kali)-[~/vulnHub/TommyBoy1]
└─# ffuf -u http://192.168.56.129:8008/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.129:8008/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 300, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 300, Words: 22, Lines: 12]
.hta                    [Status: 403, Size: 295, Words: 22, Lines: 12]
                        [Status: 200, Size: 295, Words: 35, Lines: 13]
index.html              [Status: 200, Size: 295, Words: 35, Lines: 13]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12]
:: Progress: [4614/4614] :: Job [1/1] :: 4853 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
````

# Port 80 (HTTP)

1. Proceed to `/robots`
   ````
   ┌──(root💀kali)-[~/vulnHub/TommyBoy1]
   └─# curl http://192.168.56.129/robots.txt
   User-agent: *
   Disallow: /6packsofb...soda
   Disallow: /lukeiamyourfather
   Disallow: /lookalivelowbridge
   Disallow: /flag-numero-uno.txt
   ````

1. Proceed to directories in robots.txt
   * `/6packsofb...soda`
     ![TommyBoy1 6packsofb...soda.png](TommyBoy1%206packsofb...soda.png)
   * `/lukeiamyourfather`
     ![TommyBoy1 lukeiamyourfather.png](TommyBoy1%20lukeiamyourfather.png)
