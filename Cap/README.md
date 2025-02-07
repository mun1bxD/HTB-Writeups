<img src="Imgs/image1.png" alt="error loading image">

## Cap: Easy

**Step1:**

Find open ports

<img src="Imgs/image2.jpg" alt="error loading image">

**Step2:**

Go with port 80 

<img src="Imgs/image3.jpg" alt="error loading image">

We have a web application running

Apply a directory busting to find endpoint

<img src="Imgs/image4.jpg" alt="error loading image">

Here we have an endpoint /data

**Step3:**

On /data check any IDOR exist

<img src="Imgs/image5.jpg" alt="error loading image">

Yes, there exist an IDOR vulnerability

**Step4:**

Find all endpoint using burp suite intruder

Here result show there are endpoints, at each we have a Wireshark file with download button.

Download all file

<img src="Imgs/image6.jpg" alt="error loading image">

Only we are interested in 0.pcap file because it contains lots of packet where other files contain 1 or 0 packet

File at endpoint /data/0

<img src="Imgs/image7.jpg" alt="error loading image">

File at another endpoint have 0 or 1 packet

<img src="Imgs/image8.jpg" alt="error loading image">

**Step5:**

Open file in wire shark 

<img src="Imgs/image9.jpg" alt="error loading image">

For FTP packet follow TCP stream.

<img src="Imgs/image10.jpg" alt="error loading image">

Here we can see a username and password.

As we know there is ftp and SSH running on port 21 and 22.

**Step6:**

Try with SSH first

<img src="Imgs/image11.jpg" alt="error loading image">

Now here we have user.txt which contain flag

<img src="Imgs/image12.jpg" alt="error loading image">

**Step7**:

Now we have to escalate privilege to be an admin or root

Now we have binary on this machine has special capabilities that can be abused to obtain root privileges.

Command: `getcap -r / 2>/dev/null`

<img src="Imgs/image13.jpg" alt="error loading image">

Here we see `/usr/bin/python3.8` use it to be an admin

Command: `python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

<img src="Imgs/image14.jpg" alt="error loading image">

And we have flag user root

<img src="Imgs/image15.jpg" alt="error loading image">
