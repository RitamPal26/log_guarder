import random
from datetime import datetime

ips = ["192.168.1.15", "103.25.12.8", "172.16.0.5", "110.12.45.9"]
users = ["ritam", "admin", "root", "guest", "deploy"]

with open("test_auth.log", "w") as f:
    for i in range(100):
        time = datetime.now().strftime("%b %d %H:%M:%S")
        ip = random.choice(ips)
        user = random.choice(users)
        
        # Simulate an attack from one specific IP
        if i > 50 and i < 80:
            status = "Failed password for"
            ip = "10.0.0.99"
        else:
            status = random.choice(["Accepted password for", "Failed password for"])
            
        line = f"{time} server1 sshd[{1000+i}]: {status} {user} from {ip} port {random.randint(30000, 60000)} ssh2\n"
        f.write(line)
