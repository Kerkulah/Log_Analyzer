import time
import random

# <<<< simulatting log generation for testing 
log_lines = [
    "Jun 17 14:36:39 host sshd[1031]: Accepted password for user5 from 10.0.0.14 port 80 ssh",
    "Jun 17 14:37:41 host sshd[1032]: Accepted password for user1 from 192.168.1.101 port 80 ssh",
    "Jun 17 14:37:36 host sshd[1033]: Failed password for root from 10.0.0.12 port 22 ssh2",
    "Jun 17 14:36:48 host sshd[1034]: Failed password for invalid user user2 from 203.0.113.52 port 80 ssh",
    "Jun 17 14:39:21 host sshd[1035]: Failed password for user3 from 203.0.113.51 port 80 ssh2",
    "Jun 17 14:36:29 host sshd[1036]: Accepted password for admin from 10.0.0.14 port 80 ssh",
    "Jun 17 14:40:06 host sshd[1037]: Failed password for root from 198.51.100.15 port 80 ssh",
    "Jun 17 14:39:04 host sshd[1038]: Failed password for admin from 203.0.113.50 port 22 ssh",
    "Jun 17 14:37:58 host sshd[1039]: Accepted password for invalid user guest from 203.0.113.52 port 80 ssh",
    "Jun 17 14:41:24 host sshd[1040]: Accepted password for invalid user root from 172.16.0.6 port 80 ssh"
]
while True:
    with open("sample_logs/syslog_sample.log", "a") as f:
        f.write(random.choice(log_lines) + "\n")
    time.sleep(5)
