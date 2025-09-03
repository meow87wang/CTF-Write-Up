# Crypto
## oooo

### Challenge's source code
```python3
#!/usr/local/bin/python3
import random; FLAG = open("flag.txt", "rb").read(); print("welcome to oooo")
while True: print(bytes(a^b for a, b in zip(FLAG, random.sample(range(0, 256), k=len(FLAG)))).hex() if input() != "exit" else exit())
```

### Brief
Let the flag length be $N$. 

In every round, the challenge choose $N$ numbers from `[0,255]`, shuffle them as the key stream, and then xor it with the flag.

For example, it can choose [1,255,3,7] to xor with a flag whose length is 4, but can neither choose `[1,1,240,241]` (repeated `1`) nor `[0,1,2,256]` (out of range).

### Approach
Because we know the format of the flag, which is `corctf{...}`, we can know the first 7 numbers of key stream.

This generate some 'bias' in the latter part of ciphertext.

For example, if the first 7 numbers of key streams are `[0,1,2,3,4,5,6]`, then the 8th character of plaintext `p[7]` cannot be in 
```python
[i ^ c[7] for i in range(7)]
```
where `c[7]` is the 8th character of ciphertext.

As a result, we can eliminate some candidates of each position every round.

After enough rounds, there will be only one candidate left for each position.

### Code to solve the challenge
```python3
from pwn import *
N = 112//2 # Got the length of the flag in advance.
flag = 'corctf{'

client = remote('ctfi.ng', 31556)
client.recv()
test = 1000
count = [[0]*256 for _ in range(N)]
for i in range(test):
    if i%30 == 29:
        # refresh the connection
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

    # Add 1 to valid candidates of each position
    for k in range(len(flag), N):
        for j in range(256):
            if j in used:
                continue
            count[k][j ^ res[k]] += 1

# The actual plaintext must been added every round.
for k in range(len(flag), N):
    for j in range(256):
        if count[k][j] == test:
            flag+= chr(j)
            break
print(flag)
```
