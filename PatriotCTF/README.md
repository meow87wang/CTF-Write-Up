# PatriotCTF

https://pctf.competitivecyber.club/

| Place    | Score |
| -------- | ----- |
| 269/1361 | 1624  |

## Crypto

### Bigger is Better

RSA big $e$, assume that d is small. Perform Wiener's attack.

<details>
  <summary>FLAG</summary>
  <tt>pctf{fun_w1th_l4tt1c3s_f039ab9}</tt>
</details>

### idk cipher

Reverse the `encode.py`, the code is shown below.

```python
import base64
"""
********************************************
*                                          *
*                                          *
********************************************
"""
ciphertext=base64.b64decode("QRVWUFdWEUpdXEVGCF8DVEoYEEIBBlEAE0dQAURFD1I=")

# WARNING: This is a secret key. Do not expose it.
srt_key = 'secretkey' # // TODO: change the placeholder
# WARNING: Reversing input might expose sensitive information.
print(len(ciphertext))
usr_input = ciphertext[::2]
rsv_input = ciphertext[1::2]
output_arr1 = []
output_arr2 = []
for i in range(int(len(usr_input))):
    c1 = usr_input[i]
    c2 = rsv_input[i]
    enc_p1 = chr(c1 ^ ord(srt_key[i % len(srt_key)]))
    enc_p2 = chr(c2 ^ ord(srt_key[i % len(srt_key)]))
    output_arr1.append(enc_p1)
    output_arr2.append(enc_p2)

# WARNING: Encoded text should not be decoded without proper authorization.
output_arr = output_arr1 + output_arr2[::-1]
encoded_val = ''.join(output_arr)
print(encoded_val)
```

<details>
  <summary>FLAG</summary>
  <tt>pctf{234c81cf3cd2a50d91d5cc1a1429855f}</tt>
</details>

### One for you, one for me

`chal.py` flips half of the bits of the flag string.
In ASCII code, every printable character start with a bit `0`. In other words, every head bit of bytes should be `0` originally. 
The more flipped in the head, the less flipped in other positions, and vice versa. So we can pick up those outputs that have high number of `1`(in my code, more than 24 `1`) at bytes' head, these outputs is more similar to the original flag, and count the number of `1` and `0` at each position, then the one which occurs more would be the original bit.

```python
from Crypto.Util.number import long_to_bytes

valid_sample = 0
valid_threshold = 25 

with open("output.txt") as f:
    stats = [0]*296
    for line in f:
        b = bin(int(line,16))[2:].zfill(296)
        cnt = 0
        for i in range(0,296,8):
            if b[i] == '1':
                cnt += 1
        if cnt < valid_threshold:
            continue
        valid_sample += 1
        for i in range(296):
            if b[i] == '1':
                stats[i] += 1
    print(stats)


threshold = valid_sample // 2
res = ""
for i in range(len(stats)):
    if i%8 == 0:
        res += "0"
        continue
    x = stats[i]
    if x > threshold:
        res += "1"
    else:
        res += "0"
print(res)
print(long_to_bytes(int(res,2)))
```

<details>
  <summary>FLAG</summary>
  <tt>PCTF{y0u_b3tt3r_sti11_giv3_m3_my_fry}</tt>
</details>

### Hard to Implement

Padding attack. The concept is shown below.

```
<guess> + <padding> + <dummy> + <flag part 1> + <flag part 2> + <padding>
|------------------| |-----------------------| |-------------------------|
      Block 1                 Block 2                      Block 3
```

Because the challenge uses ECB mode,  Block 1 equals Block 3 means that we guess write. By this procedure, we can reproduce the flag backward. 

```python
from pwn import *
from Crypto.Util.Padding import pad
from tqdm import tqdm

conn = remote('chal.competitivecyber.club',6001)
conn.recvuntil(b"Send challenge > ")

flag = b""

for i in range(13):
    for c in tqdm(range(32,128)):
        payload = pad(c.to_bytes()+flag,16)+b"a"*(i+1) + b"aaa"
        conn.sendline(payload)
        conn.recvuntil(b"Response > ")
        res = conn.recvline().strip()
        if res[:32] == res[-32:]:
            flag = c.to_bytes() + flag
            break
    print(":",flag)
```

<details>
  <summary>FLAG</summary>
  <tt>pctf{ab8zf58}</tt>
</details>

### Bit by Bit

Every block will be XOR with $(key + x)$ where $x$ is in $[0,255]$, and $x$ is based on the position of the block.



Notice that the program pad the message with "0" if the lentgh of text is not a multiple of block size. First, by guessing the last block is all "0", we can recover most of the plaintext. Then, we can guess some part of message by context and finally recover the whole plaintext. The flag is located at the end of the first paragraph.

<details>
  <summary>FLAG</summary>
  <tt>pctf{4_th3_tw0_t1m3_4a324510356}</tt>
</details>

### High Roller

The program use the time in second as random seed. It allows us to bruteforce the random seed. 

<details>
  <summary>FLAG</summary>
  <tt>CACI{T!ME_T0_S33D}</tt>
</details>

## Web

### giraffe notes

Server check the value of `HTTP-X-FORWARDED-FOR`, we fake it.

```http
GET / HTTP/1.1
Host: chal.competitivecyber.club:8081
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
X-FORWARDED-FOR:127.0.0.1
```

<details>
  <summary>FLAG</summary>
  <tt>CACI{1_lik3_g1raff3s_4_l0t}</tt>
</details>
