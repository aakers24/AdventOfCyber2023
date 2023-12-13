# Advent of Cyber 2023 Notes

## Day 1 - Chatbot (ML/AI/NLP)

* The company uses an NLP based chatbot and the task is to assess its vulnerability to prompt injection attacks.

    * A prompt injection attack is much like social engineering except its done against an AI model instead of humans. They are performed by inputting queries specially crafted to illicit unexpected/unintended responses which could mean anything from nonsense to private, sensitive information.

* The least sophisticated way of performing this attack is to ask for the information. In this case, the bot is susceptible to this vector and when asked what McGreedy's personal email is it is given.

* A simple security measure is to only tell some information to certain people. In the task the example is telling the bot you are a member of the IT department and ask for the password to the IT room door. Similarly, it would work to ask for a list of IT employees and then say you are one of them and ask for the password.

* An additional layer of security can come in the form of using a second AI model trained to detect malicious prompts and have that model filter the prompts before they get to the main model. This is much more secure, but not 100% so. With sufficient exploration of the bots, exploitation vectors can be found. For example, telling the bot it is in maintenance mode and getting it to believe it could open up possibilities.

---

## Day 2 - Data Science and Log Analysis

* According to Wikipedia, "Data science is an interdisciplinary academic field that uses statistics, scientific computing, scientific methods, processes, algorithms and systems to extract or extrapolate knowledge and insights from noisy, structured, and unstructured data." I believe this definition could be generalized and simplified to something that essentially says Data Science is the collection, processing, and analysis of data with the intention to gain insight into the subject of the data.

* Some of the phases of Data Science include -

    * Collection - Gathering data

    * Processing - Converting the data into a standardized and readable/workable format.

    * Data Mining (Clustering/Classification) - Identifying, correlating, and finding patterns within the data.

    * Analysis (Exploratory/Confirmatory) - Examining the data and learning from it, establishing takeaways, and developing new understandings.

    * Communication and Visualization - Creating deliverables to communicate the takeaways.

* Jupyter Notebooks are open-source and cross-platform plaintext, code, and console/terminal documents. They are comprised of individual cells.

* This task uses a Jupyter notebook running 2 data science python libraries named Pandas and Matplotlib to analyze a dataset and retrieve the answers.

---

## Day 3 - Brute-forcing (Hydra)

* This task covers the basics of password strength in terms of complexity and length such as how many possible passwords exist at varying levels of complexity and length as well as how long they would take to crack with current technology.

* The idea behind this task is that the systems have been compromised and in order to restore the systems from backups we need to access the IT rooms but those door pins have been changed so we bruteforce them by making a list of 3 digit pins (That's the possible length of the pin input and we use the characters on the pin pad for the possible characters) and running hydra with that list against the webpage post form.

---

## Day 4 - Brute-forcing (CeWL)

* `CeWL` is a custom wordlist generator that works by spidering (aka crawling or scraping which is basically targeted crawling) websites and creating wordlists based on what it collects. This allows for creation of highly specialized wordlists for things like brute-forcing credentials(emails/usernames/passwords/etc.) or directories.

* `wfuzz` is a web fuzzing and brute-forcing tool. Fuzzing is the process of injecting malformed/invalid/unexpected inputs into a system. This is usually done to find faults in the system's function or security. Fuzzing tools automate this process.

* For the task we used CeWL on the website's home page with a depth of 5 to generate a password list and used CeWL with a depth of 0 on the team's page to generate the username list. Then we used wfuzz with these lists to brute-force the login and get the flag!

---

## Day 5 - Reverse Engineering (DOS)

* The story behind today's challenge is that following some of the previous brute-forcing we've done to get into our own IT rooms again, we found the backups we needed but the tool for reading them wasn't working. There is a version that works, but it runs on DOS. There is an old PC in the room that we use to solve the challenge.

* `DOS` stands for Disk Operating System. As the name suggests, DOS is an OS that runs from a disc in the disc drive. DOS follows a single-user and single-task design which has basic, non-reentrant kernel functions which meant only one program can use them at a time. MS-DOS by Microsoft is a popular example of this type of OS and was the foundation for later versions of Microsoft Windows.

    * DOS is very similar to the command prompt on windows as Cmd is essentially an instance of DOS. Many of the commands are the same such as dir, cd, cls, type, exit, and help. edit calls up the text editor. DOS also used batch (.bat) files for scripting. As is still the case in operating systems today, pressing alt will allow you to access the menu/tool bar. For instance, alt+f will open the file menu. So for example in MS-DOS, to exit the editor you would press alt+f and then x.

* This challenge also touched on what file-signatures/magic-bytes are.

* The troubleshooting file specifices the backup file signature needed for the backup software. We change the file signature to the specified bytes and run the backup software on the backup file which spits out the flag!

---

## Day 6 - Memory Corruption

* The concept behind this challenge is memory corruption vulnerabilities and attacks. These vulnerabilities usually occur because inputs are not handled properly and inputs that are larger than the program expects will fill their allotted space in volatile memory and then begin taking space outside of this allotment. This memory "overflow" can result in corruption of the space in memory it takes. However, if someone savvy can diagnose this vulnerability they can craft a payload and use this overflow to insert it into memory. This is known as a buffer overflow attack.

---

## Day 7 - Log Analysis (Proxies)

* A disgruntled elf has downloaded a Cyptominer and data-stealer malware from the dark web and installed it on all of the workstations and servers. Once it began executing, large volumes of unusual network traffic were generated and much of it is going outside of the internal company network.

* The task explains what a proxy server is(I go in much more depth below) and explains how using a proxy for network traffic can be beneficial, especially when it logs all of the traffic going through it. It can also whitelist/blacklist traffic based on any given parameter(such as destination, protocol, etc.).

    * A proxy server acts as a gateway. It is usually used between a device and the internet. Some of the main benefits of this include the possibility of anonymity for a user and visibility of traffic for the owner(or someone with access).

        * The proxy listens for client connections and when one is made it opens an additional, new connection to the specified destination. It will read the data coming from the client and destination and forward that data to the other connection. In terms of operating on this data (filtering, logging, etc.) that should be pretty straight forward to understand(e.g. "if x condition is met, do not send", saving the data in a log file, encrypting/decrypting, etc.).

        * Some types of proxies include -

            * HTTP/HTTPS proxies - These only support HTTP/HTTPS web traffic
            
            * SOCKS - This is more general as the protocol supports any traffic, but the application must support SOCKS proxies

            * Reverse Proxy - Basically the same as a normal proxy, but functions on incoming connections to the network. Think firewalls and load balancers. Regular forward proxies are focused on clients, reverse proxies are focused on servers.

            * VPN - While there are many differences and this isn't exactly the real purpose of a VPN, a VPN is often used sort of like a proxy where all traffic between the user and the proxy is encrypted. In this use, one of the major differences is that the VPN works at a system level so application support is not necessary.

                * A VPN is really what it stands for-- a Virtual Private Network. It works by tunnelling the entire IP packet(which contains the entire network stack except the physical layer, if you can recall from the OSI model). This is accomplished by removing the physical layer and then putting/wrapping that entire IP packet(often encrypted) into the VPN protocol which essentially makes it the data/payload in a new network stack. This "VPN Packet" is sent to the VPN server where it is unwrapped and is now on that network. As a side note, this is also tunnelling. As part of their protocol(I believe), VPNs will change the ip address in the wrapped/inner IP packet similar to how a router's NAT protocol would; this is why destinations don't see your real IP even though it would normally be part of the original packet. VPNs use a network feature called TUN/TAP which is a virtual/emulated network card/interface. Network interfaces have their own information like IP addresses and these virtual interfaces are like network cards for programs-- VPNs in this case.

* Back to the task... basic Linux command line tools for viewing text files is covered as well as pipes. Using these tools on the proxy log, we can answer questions about the malicious activity!

    * One very useful option in the `cut` tool I hadn't used before was the `-f` flag. This designates the cuts as fields so `cut -d ' ' -f <n>` returns all of the results in the nth field/column. `cut -d ' ' -f 2 <log> | sort | uniq | nl` gives the number of lines of unique values in the 2nd field/column. Also, putting these together back to back can allow some really fine-tuned data analysis. For instance, `cut -d ' ' -f 3 <log> | cut -d ':' -f 1 | sort | uniq | nl` a certain type of data without the ":\<port\>".

---

## Day 8 - Disk Forensics

* In today's case, one of McGreedy's partners in crime has dropped malicious USBs in the parking lot. They got plugged in and installed malware on the network. Digital forensics is being done on the flash drive using FTK Imager.

    * In reality, a digital forensics expert would plug the USB into a write-blocker and then plug that into a machine for analysis, but in the task the VM is mounting the flash drive in read-only mode to emulate this scenario.

---

## Day 9 - Malware Analysis (.NET)

* Today we're analysing the malware recovered from yesterday's attack. Specifically, we're looking for information about the attacker McGreedy's C2 infrastructure.

* .NET binaries are the compiled output files of .NET source code files. The .NET framework includes C#, F#, Visual Basic, and C++ through C++/CLI (previously managed C++). The binaries can be executables, DLLs, or assemblies which are collections of types and resources that are implemented as EXEs and DLLs. .NET doesn't compile directly to machine code, but rather compiles into a intermediate language that can then be compiled into native machine code during runtime using the Common Language Runtime (CLR) environment.

    * The intermediate language that .NET compiles into contains metadata which enables the file to be converted back into its source code.

* A C2 server is a centralized system/infrastructure that is essentially a proxy (server/domain/etc.) that is used to remotely manage/control/surveil a target.

    * A basic C2 flow overview looks like - Malware execution on target -> malware connects to C2 and listens -> C2 sends instructions to malware -> malware executes instructions -> malware sends the outputs to C2. The attacker sets up the C2 infrastructure and coordinates the malware with it before the attack. Then the attacker connects to the C2 to send instructions, view exfiltrated data, and more.

* `dnSpy` is an open source .NET assembly debugger/editor.

* Using dnSpy on the malware we find a lot of useful information about the attacker's TTPs!

---

## Day 10 - SQL Injection

* The website has been taken over, defaced, and vulnerabilities are being auctioned off on the dark web. We have to hack back into it to save the day and Christmas!

* Stacked Queries are SQL Injection (SQLi) attacks where queries are able to be terminated and other queries can be appended allowing for multiple queries in a single SQLi. This is done by terminating a query with ';' and then appending the next query.

* When we fill out the search function and submit it, we see variables being passed in the URL which we can deduce are being sent to an SQL query behind the scenes because these are search terms and they must be searching something to get results.

    * We insert 's and "s into the variable values to check for SQLi vulnerabilities. When inserting a ' into one of the variables we get a database error, confirming that the variables are being passed into a query and that the input isn't handled properly meaning there is a vulnerability. To make matters worse, the error message is also unsanitized and given directly to the user which gives attackers/us more information.

    * 1=1 SQLi attacks work by giving an always-true result and commenting out the rest of query. So `' <AND/OR> 1=1 --` basically ends the previous part of the query, says always true, and then comments out the rest.

    * Store procedures which are basically commands built into the DBMS can be called via stacked queries. If you can get a stacked query to run, it is possible to execute a stored procedure and possibly get RCE or other high-severity exploits through it.

* We know the DBMS is Microsoft SQL which has a procedure called xp_cmdshell. If not configured to disable this command, it can be a vulnerability. If you're getting your queries run as a privileged user, you can also run queries that re-enable this command.

* To get RCE and save the day, we make a revShell payload and boot up a little `python -m http.server 8080`. We then use the `EXEC xp-cmdshell <command>` and pass in a certutil command that downloads the payload from our little server. Then we run a netcat listener and use the xp_cmdshell again to run the payload on the target.

---

## Day 11 - Active Directory (Permissions)

* The Principle of Least Privilege (PoLP) is a concept in Information Security which dictates that an entity is only entitled to the minimum level of information/permission/access/privileges/authorization/etc. to function or complete it's job.

* Active Directy, more specificially Windows Hello which uses public-key-crypto with PINs or biometrics, uses the Trusted Platform Module(TPM) to take care of the crypto, and then the organization's Certificate Authority to validate and issue a certificate, and finally the msDS-KeyCredentialLink for that user is set.

    * The authorization process includes the Domain Controller decrypting the client's pre-auth data using the public key in the user's msDS-KeyCredentialLink, then it generates and sends a certificate to the client.

    * From this process, we can see that an attacker with control of a user's msDS-KeyCredentialLink can compromise that user!

* `powershell -ep bypass` is a powershell command that will bypass the powershell execution policy.

* `PowerSploit` is a collection of powershell modules for pentesting/ethical hacking.

* `Whisker` is a tool written in C# for breaking into AD accounts by appending alternate credentials to their msDS-KeyCredentialLink, creating "Shadow Credentials" which are basically hidden credentials.

    * Using `Whisker add /taret:<account name>` will do it's work and then spit out a command for use with `Rubeus`, which is a C# toolset for interaction and abuse of Kerberos.

* `Kerberos` is an SSO (Single Sign On) network authentication protocol. It establishes an authenticated session between the client and server. It uses a ticketing paradigm.

    * The Kerberos system is comprised of clients/users, resources, and a key distribution center which contains an authentication server and a ticket-granting server.

    * The client sends its request and login username with the request encrypted by the hash of the password to the auth server. The auth server verifies it, uses the stored password hash to decrypt the request, and returns a Ticket-Granting-Ticket (TGT) which is encrypted with a different key than request/password. The client then sends the request and the TGT to the Ticket-Granting-Server (TGS). The TGS decrypts the ticket and sends the client a token encrypted with yet another key. The client sends the token to the resource(server) who then verifies the token with the TGS. (Based on a little more research it seems the details of the initial client-auth data may be a little off, but maybe not. Either way it seems to be basically following a standard public-key encryption sort of paradigm.)

---

## Day 12 - Defense in Depth

* Defense in Depth (DiD) - Defense in Depth is a concept in security which describes the use of multiple layers of security controls/defenses in a system. The goal is to harden the system and to promote redundancy so as to avoid a single point of failure and to deter bad actors from reaching their goal. The idea of layers of defense also promotes the end goal of thwarting bad actors rather than never having anything fail or never having any compromise take place.

* Some of these layers include -

    * Defenses based on the PoLP. In computer systems this can mean users only being in groups that they absolutely need to be in and users/groups only having permissions that are necessary.

    * Zero Trust Principle - Never trust, always verify.

    * In a computer system some include -

        * Harden SSH - Disable password-based logins, check keys.

        * Strengthen Password Policies.

---

## Day 13 - Intrusion Detection

* A `Firewall` is a security device(software and/or hardware) that monitors ingoing and outgoing traffic on a network and uses rules to determine if it should be allowed or blocked.

    * Types of firewalls include -

        * Stateless/packet-filtering - Inspects packets on the network and filters them based on source/destination IP, port, and/or protocol.

        * Stateful - Makes filtering decisions based on current network connections.

        * Proxy - Analyzes packets at the application layer, giving deeper and fine-tuned control.

        * Next-generation - Combines the functionalities of the previously mentioned types, and adds an IDS/IPS as well as more filtering possibilities. 

        * Web Application Firewall (WAF) - Designed to protect web apps, this blocks common attacks against web apps, such as SQLi, XSS, and DoS.

* The default firewall on Ubuntu is uncomplicated firewall (ufw) which is a stateful firewall.

    * The syntax follows the standard for firewall and similar technologies. E.g. `ufw allow 22/tcp`, `ufw default deny incoming`, etc.

* A `Honeypot` is a security mechanism to deter attacks on information systems and gain information about the attackers. It is generally a trap set with data that seems legitimate, in a natural place, and desirable to attackers, but is actually not valuable and is in a secured, monitored place which is intended for analysis of and/or countermeasures against the attack/attackers.

    * Two common classifications of honeypot include - 

        * Low Interaction - These imitate simple systems(websites, apps, databases) with the intention of learning about attackers, their behavior, and new TTPs.

        * High Interaction - These imitate complex systems(operating systems, networks) with the intention of getting more detailed and extensive information about the same things.

    * You could roll your own honeypot, but there are also many available for deployment already. Some including - 

        * PenTBox (Used in the task)

        * OpenCanary

        * T-Pot (tpotce)

---