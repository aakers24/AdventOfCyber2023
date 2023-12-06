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

    * DOS is very similar to the command prompt on windows as Cmd is essentially an instance of DOS. Many of the commands are the same such as dir, cd, cls, type, and help. edit calls up the text editor. DOS also used batch (.bat) files for scripting. As is still the case in operating systems today, pressing alt will allow you to access the menu/tool bar. For instance, alt+f will open the file menu. So for example in MS-DOS, to exit the editor you would press alt+f and then x.

* This challenge also touched on what file-signatures/magic-bytes are.

* The troubleshooting file specifices the backup file signature needed for the backup software. We change the file signature to the specified bytes and run the backup software on the backup file which spits out the flag!

---