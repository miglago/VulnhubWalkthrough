# About
This Machine deals with a WordPress Vulnerable Server - We have to find the login to the Wordpress Admin account then use that information to gain a reverse
shell through MetaSploit Framework. After gaining access to the Webserver, we can then seek to elevate our access by exploiting an old version of NMAP
which had an interactive Shell Mode

## Setting up the Environment 
First we have to set up our Virtual Machine Environment. In this case – I am using a Windows machine as the host. VirtualBox is set up with a Kali Linux installation and the OVA file of the vulnerable Machine – The Network configuration has to be set to Host Only Adapter between the Vulnerable Machine and the Kali Machine to allow the machines to communicate with each other.


## Network Scanning
Since both machines are connected to each other – IE: On the same network through a Host only Adapter – We can easily find the vulnerable machine by doing a netdiscover command on our IP. 

For Reference:
| Command | Purpose | 
| --- | --- |
|ifconfig | To find the IP address and display Network information |
| Netdiscover –r (IP)| The –r flag is for range followed by our IP – To find all hosts within our network by sending ARP Requests  | 

Once you run Netdiscover – We discover 2 hosts in the system 
– Though in other machines you might find more than 2 hosts depending on the set up. Finding out the right host in the list of host is relatively easy – It would usually be followed by the “PCS Systemtechnik GmbH message” Though if you are still unsure – Just run an nmap scan on each out of the outputs of Netdiscover – Then using the output of Nmap you can determine if the IP corresponds to the vulnerable machine. 

NMAP Reference:
| Flag | Purpose | 
| --- | --- |
| -F | Fast mode |
| -O | OS fingerprinting |
| -A | Common Ports and used Scripts |
| -sS | Stealth Syn Scan - Most popular scanning option - Quickly with thousand of ports | 

In this case, i will ben running nmap with O flag and F flag to find out the OS and fast mode - Since i don't need to scan through all ports - Just common ones
After the NMAP Scan is done, we discover that there are a couple of ports open:
Ports Reference:
| Port | Service | Purpose | 
| --- | --- | --- |
| PORT 80 | HTTP | Webserver running on the IP|
| PORT 443 | HTTPS | Secure WebServer |
| PORT 22 | SSH | Secure Shell for Remote connection |

We discover that the IP is running a webserver - Which means, we can boot up FireFox and visit the webserver by using the IP of the machine.
Once we go to the IP - We find out the webserver - Nothing of value can be found here, so instead of wasting our time, we can run some webserver scanners

##  Web Server Vuln Analysis
There are a lot of tools out there to scan a webserver for vulnerabilities - The most common one is Nikto but we can also use other tools like Nmap to run a 
basic Web enumeration so we can get info on the webserver. We will be using both techniques here to get the most info we can before deciding on the method to attack.

### Nikto
Nikto is a command Line interface based Vulnerability scanner for Webservers - Kali comes with Nikto Preinstall so its a quick and useful way to scan. We can use 
Nikto straight on the command line.  
Set up Nikto to scan a host with an IP by using **nikto -h (IP)** with the -h flag for host then making reference to the IP. 
You can also pipe the output into a textfile with > 
But in this case we will just print the output into the terminal. 
### NMAP Web Enumeration
While we can use Nikto to scan a webserver - We can also use NMAP to find out information about the webserver. Often time this method might be more useful if all we need is just information on the webserver such as 
subfolders. 
NMAP has an integrated scripting engine – NSE – Nmap Scripting Engine – It allows users to write and share scripts using the Lua programming Language to automate various networking tasks which then are executed. In this case we can either code our own script our use a pre existing one. 
We can use the Nmap http-enumeration script to enumerate the directories giving us information on the web server contents.     

We can run this script by calling on nmap with the script flag then making reference to the script  **nmap -script http-enum.nse (IP)**  

--------------------
After running both Nikto and the enumeration script on the webserver - We gain a lot of information on the webserver - But the most important pieces of 
information we need to consider are the directories.

We discover:
* Login prompt at wp-login
* TextFile at /Robots.txt
* ReadMe at /readMe

There are some other directories but they don't contain useful or relevant information. 

But lets explore the other directories. 

Wp-login is a word press login with username and password field.

Robots.txt contains two files – A dictionary file and a text file named “key-1-of-3.txt” the first of 3 keys hidden in this system. 

Now to download these files we can directly go to the sub directory or use web tool to download the files by making a request to them. 

To download both these files - We can use a tool specifically made to retrieve/download content from web servers. This tool Wget is part of the GNU program and usually comes preinstall with  most linux distributions as a default package.
We can get both files noted above by using wget on the webserver directory that contains the files. 

| Command | File
| --- | --- |
| wget (IP)/fsocity.dic | download the dictionary |
| wget (IP)/key-1-of-3.txt | to download the text file with the key|

Once we have the key text file - We can either open it or concatenate to find out its content. Once we do – We discover the key. 

## Password Cracking

What about the dictionary file? We can also concatenate to show its content but this file is pretty big and contains multiple copies of the same entry – So we need to filter it. We can do a word count on the file to find out the file contains over 80,000 individual new line entries – That is a little too much. So we can filter out the duplicates and generate a new dictionary based on the pre existing one. This can save on time and memory since it won’t have to check for duplicate entries once we try brute forcing the login. 

Using the command line we can run **sort fsocity.dic | uniq | wc** to filter the list by new entries and give us the word count. 
Only 11451 entries? So much better – And now we can repeat the above command but pipe it into a new file. 

What about that wordpress login form at wp-login? 

We can try any combination but it gives us wrong username – So it first does a username check it and as we later find out – If we try the right username but wrong password – It will give us an invalid password check

There is no limit on the number of tries per account which means we can run a brute force on this login prompt until we discover the right login credentials. 

Let’s use the filter dictionary we created to save on time and resources. Using Hydra – A linux tool for brute forcing login attacks – We attach an http form to the hydra command since we are brute forcing into an http form. 

We can use the command:  **Hydra –L ./fsocity_new.dic –P ./fsocity_new.dic (IP) http-form-post “/wp-log.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username”**

Hydra command Reference
| Part | Purpose |
| --- | --- |
| -L | Try all usernames from the dictionary |
| -P | Try all passwords from the dictionary |
| http-post-form | Brute Forcing an HTTP Post Form - Request to the webserver to accept the data |
| /wp-login.php | Dictionary of the word press login prompt |
|log=^USER^&pwd=^PASS^&wp-submit=Log+In | Post Parameter | 
| ^USER^ and ^PASS^ | Placeholders that will be replaced with actual login |
| F=Invalid username | Attempt failure if the reponse matches the string | 

|Note|
|---|
|While we use Hydra here, we can use other tools like wpscan |

The scan will take about 4 mintues or so depending on computer resources but once its all done - We discover the login:

Now since we have both the username and password -We can try the wordpress site again at /wp-login
Successful login! 

## WordPress Reverse Shell
Now we have gained access to the wordpress admin account – But we want a shell into the actual machine. There is a metasploit exploit for wordpress. So we can boot up the metasploit framework either by clicking on the application shortcut or using **msfconsole**  on the terminal. 

So many exploits in metasploit? Which can we use? Lets try filtering out the exploit database to find something we can use – But what are we looking for?Well – We know we have a wordpress server – We know we want a shell and we know we have admin access – So maybe filter the list by wordpress, admin, shell? 

After filtering the list, we discover an exploit: “wp_admin_shell_upload” – Seems correct so lets call on the payload and fill out the options. Every payload in metasploit has a list of options or parameters that need to be filled in before it can exploit. 

In  this case we need the following information for the payload to run
| Parameter | Info |
| --- | --- |
| PASSWORD | This is the password field for the admin account we discover earlier |
| RHOSTS | The IP of the machine being attacked |
| TARGETURI | The directory of the login |
| USERNAME | The login field for the admin account | 
| WPCHECK | Wordpress check we have to manually set to false |
| LHOST | Instead of home loop - Manual IP of local host | 

Now everything is set - So - Ready and go! Exploit the payload - This payload will create a shell with a session ID of 1 for reference.
Now we have gained access to the system - BUt its an empty shell so we need to spawn in a shell - Which we can by using the following command Python command
|Python command for shell |
| --- |
| python -c 'import pty; pty.spawn("/bin/sh")' |

Now our shell is a bit less limited but still we don't have root access to the system but thats okay for now. Now with this shell we can look through the file 
system for anything of note. 

Running ls on the system – We find some directories – The robot directory seems interesting so – CD into the robot directory then running LS to find out the contents. We discover two files. 
* Key-2-of-3.txt
* password.raw-md5

A textfile with the second Key and a hash file containing a password. We get permission denied on the key file- So by guessing, we need the password from the 
md5 hash file before accessing the text file. 

## Hash Decrypting
If we concatenate the password file – We get a weird string – This string indicates a unsalted MD5 hash. We can decrypt this hash then since its not salted. We can use a pre existing database to find out if some one already decrypted this hash – Which most likely did, but we can use our own tools. 
To decrypt this hash – We can use pre existing tools like John the ripper, hashcat, etc – Or pre existing hash databases where other people note down already decrypted hashes. 
In this case we can try both tools. 

### John The Ripper
John the Ripper is a command line based program for UNIX systems made for password cracking – More specifically hashes as long as the file is unhashed and you have some idea of the format being used though it can still be user if the format is unknown. 

First let take the string we got and make that into a file with the same file type. John and other tools like hashcat – Utilize a brute forcing technique that we saw earlier with Hydra – Utilizing a dictionary. John the Ripper comes with a default word list that can be found at **/usr/share/wordlists/rockyou**

Now we can call John the ripper – Making note of the format then indicate the path to the wordlist and to the file. 
John the ripper will spit out the decrypted password in the terminal. 

### Hashcat
We can use hashcat which like John the Ripper is an advance password cracking tool though can also be used for recovery. Though Hashcat primary focus is in recovery but with usage that extent to the security testing field.

| Flag | Purpose
| --- | --- |
| -a | attach mode |
| -m | hash type |
|-o | output | 

Then we make reference to the hashed file followed by the path to the dictionary to be used. Hashcat will spit out the output onto the terminal after the original hash.

## Nmap Interactive Mode: Privilege Escalation

Now we have the password – What now?Remember the text file with the second key? It was password protected. Lets go back to the shell.

Note – If we lost access, we can open up metasploit and gain access to the system by using the session ID created earlier.

We have a password but no user? So, what now? We can find all users on the system with multiple ways such as looking at the passwd field and checking with fields lack the nologin parameter. Or - Why don’t we go back to that text file and see whats up with it. Lets do ls –lsa  for long format on the directory. We find that the file has read permission for only robot user. So lets try to log into that user account. 

Switch user robot – Then when prompted to input the password – We use the decrypted hash. Success! We have elevated our access from regular user to robot user. Not root yet. But we can finally read the text file to find the second key file.

Now we can look around the system for ways to escalate our level of privilege within the system. We want to elevate our access to root user – Or admin level – That way we have control the entire system. There are several ways to elevate our access – Local privilege escalation, etc – Outdate software, etc. 

An interesting technique within linux deals with the SUID bit – A bit in a file that allows execution of the file as the user who owns the file regardless of the user passing the file – So if the file owner of a file is root we gain root level access by running that file as any user. 
We can find out all files that contain this bit by running the find command filter out by the permission type. **Find / –perm -4000 –type f 2>/dev/null**

Files with the permission 4000 indicate root. We see a couple of files but the most interesting one is nmap because in earlier versions of nmap – It had an interactive mode which means nmap would spawn a shell containing the same level of access as the file program had – Meaning root access. We can use nmap to gain a root shell to the entire system. 
We can call nmap interactive by making a reference to the mode using  - – interactive flag.
This will boot up a shell through which nmap and the rest of the system can be interactive with. You can check the level of acceess with a system command – whoami.

Note – Commands have to include the ! In the start so it can be parse through the nmap interactive shell and have the same level of access. 

Lets run a ls on the root folder to find out some more information now that we are not limited by our level of access. We find another text file “key-3-of-3.txt” Concatenating that file we discover the third and final key.


We have successfully gained access to the machine, found the 3 hidden keys and gain root access. 




