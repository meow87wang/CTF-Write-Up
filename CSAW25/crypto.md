# CSAW25

## Manual Distress Signal

### Description

The challange provides a website.
All text in the website is encrypted with ROT47 with `key=7`.
By reading the website's content, we can know that it is a encryption oracle, but the encryption(?) scheme is a black box.

### Observation

1. When querying empty plaintext, it output nonempty ciphertext.
2. The ciphertext length is not linear to plaintext. (e.g. `a -> xxx, aaaaaaaa -> XXXX`)
3. Different plaintext with same length output different length of ciphertext.

### Strategy

Base on above observation, I guess the website work like this:

```python
def encrypt(pt):
    secret = 'some string'
    pt = secret + pt
    compressed = compress(pt)
    ct = length_preserving_encryption(compressed)
    return ct
```

This is a typical scheme that exists compression oracle attack.

#### Compression oracle attack
Generally speaking, the more repetition in the input string, the shorter it is after compression.
For example, `compress('abca')` will shorter than `compress('abcd')`, `compress('abcab')` will shorter than `compress('abcad')`.

So we can reconstruct the secret one character by one, based on which string outputs shortest output.
The process will work like:

1. Query `'a','b','c',..,'z', ...,` (every printable char), find that `'c'`'s output is the shortest, so the first char of secret is `'c'`
2. Query `'c' + 'a', 'c' + 'b', ......`, find that `'cs'`'s output is the shortest.
3. Query `'cs'+'a', 'cs'+'b',......`, ...

### Code

```python=
import requests
import base64
from Crypto.Util.number import bytes_to_long
import string
from tqdm import tqdm

url = "https://manual-distress.ctf.csaw.io/send"


def test(s):
    r = requests.post(url, json={"data": s}) 
    r = r.json()
    if 'error' in r:
        r['error'] = rot(r['error'])
    if 'ciphertext' in r:
        r['ciphertext'] = base64.b64decode(r['ciphertext'].encode())
    return r

# ROT47 decryption, useless for solving the challenge
def rot(s):
    res = ""
    for c in s:
        if 33 <= ord(c) <= 126:
            res += chr(33 + (ord(c)-33 + 7)%(127-33))
        else:
            res += c
    return res 

msg = ''

for _ in range(100):
    min_length = 1000
    min_char = ''
    for i in tqdm(range(33,127)):
        c = chr(i)
        x = test(msg+c)
        l = len(x['ciphertext'])
        if l < min_length:
            min_length = l 
            min_char = c 
    msg = msg + min_char
    print(msg)
    if min_char == '': 
        break
```

### Flag

Didn't keep it.

## Oracle Down

### Description

The challange provides a decryption oracle.
A part of code is also provided:

```python=
import time
import hmac
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
import secrets
from random import uniform

def obfuscate_hmac(min_ms=250, max_ms=1000):
    delay_seconds = uniform(min_ms, max_ms) / 1000
    time.sleep(delay_seconds)

def encrypt_cbc(plaintext, key):
    iv = bytes.fromhex(secrets.token_hex(16))
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = iv + cipher.encrypt(pad(plaintext, AES.block_size))

    h = HMAC.new(key, digestmod=SHA256)
    h.update(encrypted)
    mac = h.digest()
    
    return mac + encrypted

def decrypt_cbc(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    
    ciph_mac = ciphertext[:32]
    ciph_ciph = ciphertext[32:]
    iv = ciph_ciph[:AES.block_size]
    ciph = ciph_ciph[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        unpadded = unpad(cipher.decrypt(ciph), AES.block_size)
    except Exception as e:
        raise Exception("Incorrect padding.")

    if len(ciphertext) != 96:
        print(len(ciphertext))
        raise Exception("Incorrect length")
    
    obfuscate_hmac()

    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciph_ciph)
    if ciph_mac != h.digest():
        raise Exception("MAC verification failed.")
    else:
        return unpadded
    

```

### Observation

In the `decrypt_cbc()`, there is `obfuscate_hmac` which lengthen the running time.
If the decryption output is padded correctly and `len(ciphertext) == 96`, then it will take longer to return.
So, as long as we query with 96 chars input, we can know whether the decryption is padded correctly.

### Strategy

Nowing the padding result allows us to perform [cbc padding oracle attack](https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/).
![image alt](https://www.nccgroup.com/media/uw1pnmge/_cbc-attack-final-byte.gif)

### Code

```python=
from pwn import *
from Crypto.Util.number import long_to_bytes
import os
import sys
from CBCpadding import CBCPaddingAttack
import time
from tqdm import tqdm

class :
    def __init__(self):
        self.client = remote('15.164.102.155', 21004)
        self.client.recvuntil(b'> ')

    # Time measurement, need sampling
    def query(self, ct):
        res = []
        if len(ct)%16 != 0:
            raise Exception('block')
        if len(ct) < 96: 
            ct = b'0'*(96-len(ct)) + ct
        for _ in range(5):
            res.append(self.subquery(ct))
        return sum(res)/len(res) > 0.7 

    # one sample
    def subquery(self, ct):
        client = self.client
        client.send(ct.hex().encode() + b'\n')
        before = time.time()
        res = client.recvuntil(b'> ')
        return time.time() - before
             

ct = bytes.fromhex(open('intercepted_transmission.txt','r').read())

prefix = ct[:32]
ct = ct[32:]

charset = '_' + string.digits + string.ascii_letters + string.punctuation
print(len(ct))


oracle = Oracle()

print(oracle.query(ct[-32:]))

if False:
    for i in tqdm(range(ct[79]-1,-1,-1)):
        msg = ct[:79] + bytes([i]) + ct[80:]
        if oracle.query(msg):
            print(i)
            break
           
attack = CBCPaddingAttack(oracle)
known_ans = ['','',''] # sometimes get outliers, this make it more easy to redo
print(attack.solve(ct, charset, known_ans))
```

```python=
import random
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import string
from tqdm import tqdm

class CBCPaddingAttack:
    def __init__(self, oracle):
        self.oracle = oracle
        
    def solve_block(self, ct, charset, known_ans):
        assert len(ct)%16 == 0
        assert len(ct)//16 == 2
        result = [0]*16
        known = len(known_ans)
        
        for i in range(known):
            result[16-known+i] = ord(known_ans[i])
        
        charset  = [ord(c) for c in charset]
        
        for i in range(known,16):
            first = [ct[j] ^ result[j] for j in range(16)]
            first = first[:16-i-1] + [first[j] ^ (i+1) for j in range(16-i-1,16)]
            answer_exist = False
            charset2 = charset + [i for i in range(0,i+1)] + [i for i in range(i+2,17)] + [i+1]
            
            for c in tqdm(charset2):
                first[15-i] ^= c
                data = bytes(first+ct[16:])
                
                if self.oracle.query(data):
                    result[15-i] = c 
                    answer_exist = True
                    break
                    
                first[15-i] ^= c
                
            if not answer_exist:
                print('Charset not cover plaintext')
                return
            
            print(bytes(result))
            
        return bytes(result)

    def solve(self,ct, charset, known_ans):
        result = b''
        assert len(ct)%16 == 0
        n = (len(ct)//16)-1
        
        for i in range(n):
            blocks = list(ct[16*i:(16*i+32)])
            result += self.solve_block(blocks, charset, known_ans[i])
            print(result)
        
        return result



```

### Flag

`csawctf{4ll_4l0n_un1v3rse}`
