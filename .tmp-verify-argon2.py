import sys, os
from argon2 import PasswordHasher

ph = PasswordHasher()
h = "$argon2id$v=19$m=19456,t=2,p=1$zi3I59Jy3q7eRbbP5QKZwQ$9RkdzoJe5siU9qlF5PnfuQTv9ud5vonAr38DjWhZKqM"
with open("/tmp/candidates.txt") as f:
    for line in f:
        c = line.strip()
        if not c:
            continue
        try:
            ph.verify(h, c)
            print("MATCH:", c)
            sys.exit(0)
        except Exception:
            pass
print("NO MATCH")
