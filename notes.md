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

## Day 3 - Brute-forcing

* This task covers the basics of password strength in terms of complexity and length such as how many possible passwords exist at varying levels of complexity and length as well as how long they would take to crack with current technology.

* The idea behind this task is that the systems have been compromised and in order to restore the systems from backups we need to access the IT rooms but those door pins have been changed so we bruteforce them by making a list of 3 digit pins (That's the possible length of the pin input and we use the characters on the pin pad for the possible characters) and running hydra with that list against the webpage post form.

---