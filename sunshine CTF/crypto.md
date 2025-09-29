# sunshine CTF

## Crypto

### Bits of Space

The server use block cipher counter mode to encrypt one message multiple times. But the counter is reused and increased by 1 every encryption.
So the key stream xor with second block in the first round, will be used to xor with the second round in the second round.
Additionally, the first block of plaintext is provided.
By this, we ca construct the whole plaintext after we get enough ciphertexts.

Encryption 1:
```
 block 1 |  block 2 |  block 3 | ...
  key 1  |   key 2  |   key 3  | ...
```

Encryption 2:
```
 block 1 |  block 2 |  block 3 | ...
  key 2  |   key 3  |   key 4  | ...
```

```python
from pwn import *
from Crypto.Util.number import long_to_bytes
from binascii import unhexlify
from string import printable

client = remote('chal.sunshinectf.games', 25403)

client.recvuntil(b'== BEGINNING TRANSMISSION ==\n\n')

n = len(client.recvuntil(b'\n').strip())//2
print(n)
blocks = n//16 + 1
queue = []

for i in range(blocks):
    res = client.recvuntil(b'\n').strip()
    queue.append(unhexlify(res))


first_block = 'Greetings, Earthlings.'[:16].encode()

msg = b''

queue = queue[::-1]
key = [a ^ b for a,b in zip(first_block, queue[0][:16])]

for i in range(1, 26):
    res = [a ^ b for a,b in  zip(key, queue[i][i*16:i*16+16])]
    msg += bytes(res)
print(msg)
```

Miss the last byte, but it definitely is `}`.

`sun{n3v3r_c0unt_0ut_th3_p1ut0ni4ns}`

### MoonClicker

### Description

The website let you enter a username. Then it will give you an encrypted cookie.
If you click the moon, server will add the count by 1 and re-encrypt the cookie.
You can modify the cookie, but it won't provide detail error message, so padding oracle will not work(and it doesn't use CBC mode).
It is straight forward to guess that you get the flag when the count is large enough.

### Observation

If enter a name like `'aa...aa'`, you will see repitition in ciphertext. This imply the use of ECB mode.
Enter the same name several times, always get the same ciphertext. This imply the reuse of secret key.

### Strategy

So we assume the plain cookie is in a format like this:
```
'{"user":"the name you enter", "count": "count"}'
```

We do this

```
              |--replacement-|
{"user":".... | a big number | ", ... | ...
```

```
|----------prefix---------|--suffix---
... | ... | ... "count":" | 0" ...
```

The set the cookie as `prefix || replacement || suffix`.
The hard part is to find the right offset.
We find the offset by adding the length of name and changing 1 character to see what blocks are different.
For name:
```
same|different| same
....|.......a | ".....
....|.......b | ".....

add one more character in name

same|  same  | different
....|....... | a".....
....|....... | b".....
```

For count we use click:
```
same|different| same
....|.......0 | ".....
....|.......1 | ".....

add one more character in name

same|  same  | different
....|....... | 0".....
....|....... | 1".....

```


### Code

```python
import requests
from tqdm import tqdm
from collections import defaultdict
import time
from string import printable

# name -> cookie
def oracle(s):
    url = 'https://kerbal.sunshinectf.games/'
    data = {'name': s}
    r = requests.post(url, data=data)
    return r.cookies.items()[0][1]

# cookie -> click -> cookie
def click(cookie):
    url = 'https://kerbal.sunshinectf.games/click'
    cookies = {'clicker': cookie}
    r = requests.post(url, cookies=cookies)
    return r.cookies.items()[0][1]

# cookie -> name + click count
def decrypt(cookie):
    url = 'https://kerbal.sunshinectf.games/'
    cookies = {'clicker': cookie}
    r = requests.post(url, cookies=cookies)
    return r.text

# first diff position of two strings.
def diff(a,b):
    for i in range(min(len(a),len(b))):
        if a[i] != b[i]:
            return i
    return min(len(a),len(b))

# checking for ECB
print('='*10 + 'check ECB' + '='*10)
print(oracle('a'*200)) # A lot of repeat, means ECB


# Find the position of name
print('='*10 + 'name position' + '='*10)
for i in range(1,32):
    a = oracle('a'*i)
    b = oracle('a'*(i-1) + 'b')
    print(i,diff(a,b))
# name start at 10 th(0-based) byte of the first block

# check where the count end at
## maybe fixed length string, but i guess the length change.
print('='*10 + 'number position' + '='*10)
for i in range(32):
    a = oracle('a'*i)
    b = click(a)
    print(i, diff(a,b))
# 25: ...???"0 | "???...
# 26:   ...???"| 0"???...
# 27:    ...???| "0"???...


print('='*10 + 'Solve' + '='*10)
lightyear = '9460730472580800000000000000000000'
replaceblock = oracle('a'*6 + lightyear)[32:64]

prefix = oracle('a'*26)[:-32]
suffix = oracle('a'*25)[-32:]

print(decrypt(prefix + replaceblock + suffix))
```

### Flag

`sun{g00d_j0b_u51ng_7h3_crumb5_70_m4k3_7h3_c00k13}`

### Note
I don't like this challenge.
Difficulty come from its black box property.
