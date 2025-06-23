import time
import random

# <<<< simulatting log generation for testing 
log_lines = [
    "Jun 17 14:36:39 host sshd[1031]: Accepted password for user5 from 144.172.79.92 port 80 ssh",
    "Jun 17 14:37:41 host sshd[1032]: Accepted password for user1 from 47.180.91.213 port 80 ssh",
    "Jun 17 14:37:36 host sshd[1033]: Failed password for root from 1.1.1.1 port 22 ssh2",

]
while True:
    with open("sample_logs/syslog_sample.log", "a") as f:
        f.write(random.choice(log_lines) + "\n")
    time.sleep(5)
