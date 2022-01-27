# NMAP Complete Scan
```
# Nmap 7.92 scan initiated Tue Jan 25 18:30:16 2022 as: nmap -vv --reason -Pn -T4 -sV -p 80 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN /root/vulnHub/Glasglow-Smile-1.1/192.168.1.1/scans/tcp80/tcp_80_http_nmap.txt -oX /root/vulnHub/Glasglow-Smile-1.1/192.168.1.1/scans/tcp80/xml/tcp_80_http_nmap.xml 192.168.1.1
Nmap scan report for 192.168.1.1
Host is up, received arp-response (0.00019s latency).
Scanned at 2022-01-25 18:30:17 +08 for 17s

Bug in http-security-headers: no string output.
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
|_http-wordpress-enum: Nothing found amongst the top 100 resources,use --script-args search-limit=<number|all> for deeper analysis)
|_http-errors: Couldn't find any error pages.
| http-headers: 
|   Date: Tue, 25 Jan 2022 10:30:24 GMT
|   Server: Apache/2.4.38 (Debian)
|   Last-Modified: Sat, 13 Jun 2020 18:53:52 GMT
|   ETag: "7d-5a7fbb701d4b6"
|   Accept-Ranges: bytes
|   Content-Length: 125
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: HEAD)
|_http-feed: Couldn't find any feeds.
|_http-config-backup: ERROR: Script execution failed (use -d to debug)
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1; jpg: 1
|   Longest directory structure:
|     Depth: 0
|     Dir: /
|   Total files found (by extension):
|_    Other: 1; jpg: 1
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-comments-displayer: Couldn't find any comments.
|_http-server-header: Apache/2.4.38 (Debian)
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-mobileversion-checker: No mobile version detected.
|_http-chrono: Request times for /; avg: 161.31ms; min: 149.31ms; max: 207.34ms
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
| http-vhosts: 
|_128 names had status 200
|_http-malware-host: Host appears to be clean
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Site doesn't have a title (text/html).
|_http-exif-spider: ERROR: Script execution failed (use -d to debug)
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
| http-php-version: Logo query returned unknown hash 91f9a8dbb5d9f959d393e53c5dada8fa
|_Credits query returned unknown hash 91f9a8dbb5d9f959d393e53c5dada8fa
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-date: Tue, 25 Jan 2022 10:30:23 GMT; -30m01s from local time.
MAC Address: 00:0C:29:4F:F2:DE (VMware)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 25 18:30:34 2022 -- 1 IP address (1 host up) scanned in 18.68 seconds

```