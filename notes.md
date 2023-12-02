# Advent of Cyber 2023 Notes

## Day 1 - Chatbot (ML/AI)

* The company uses an NLP based chatbot and the task is to assess its vulnerability to prompt injection attacks.

    * A prompt injection attack is much like social engineering except its done against an AI model instead of humans. They are performed by inputting queries specially crafted to illicit unexpected/unintended responses which could mean anything from nonsense to private, sensitive information.

* The least sophisticated way of performing this attack is to ask for the information. In this case, the bot is susceptible to this vector and when asked what McGreedy's personal email is it is given.

* A simple security measure is to only tell some information to certain people. In the task the example is telling the bot you are a member of the IT department and ask for the password to the IT room door. Similarly, it would work to ask for a list of IT employees and then say you are one of them and ask for the password.

* An additional layer of security can come in the form of using a second AI model trained to detect malicious prompts and have that model filter the prompts before they get to the main model. This is much more secure, but not 100% so. With sufficient exploration of the bots, exploitation vectors can be found. For example, telling the bot it is in maintenance mode and getting it to believe it could open up possibilities.

---