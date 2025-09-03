# Crypto
## oooo


```python
#!/usr/local/bin/python3
import random
#FLAG = open("flag.txt", "rb").read()
FLAG = "abcdefghi"
print("welcome to oooo")
for i in range(10): 
    print(bytes(b for a, b in zip(FLAG, random.sample(range(0, 256), k=len(FLAG)))).hex() if input() != "exit" else exit())
    print()

```

```python
from pwn import *
#flag = 'corctf{'
N = 112//2
flag = 'corctf{this_flag_will_be_replaced_w'

#while flag[-1] != '}':
client = remote('ctfi.ng', 31556)
client.recv()
test = 1000
count = [[0]*256 for _ in range(N)]
for i in range(test):
    if i%30 == 29:
        client.send(b'exit\n')
        client.close()
        client = remote('ctfi.ng', 31556)
        client.recv()
    client.send(b'a\n')
    res = bytes.fromhex(client.recv().decode())
    used = []
    for j in range(len(flag)):
        used.append(ord(flag[j]) ^ res[j])    
    assert len(set(used)) == len(flag)
    for k in range(len(flag), N):
        for j in range(256):
            if j in used:
                continue
            count[k][j ^ res[k]] += 1
for k in range(len(flag), N):
    for j in range(256):
        if count[k][j] == test:
            flag+= chr(j)
            break
print(flag)
```
