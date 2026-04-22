# Wreck CTF 2026

## crypto/Nonce Sense

### Challenge

`gen.py`
```python
"""
Bob runs a little 'secure' broadcast.  Each week he posts a public safety
bulletin and, separately, drops a private note to his friends -- both
encrypted with AES-CTR under the same key.

This week he also got lazy and picked the same nonce for both.
"""

from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = os.urandom(8)

bulletin = (
    b"BULLETIN: This week's safety reminders from the helpdesk. "
    b"Lock your screen when you walk away. Do not reuse passwords. "
    b"And for the love of all that is good, never reuse a nonce with "
    b"a stream cipher -- that's basically a two-time pad, and a "
    b"two-time pad is no pad at all."
)
flag = open("flag.txt", "rb").read().strip()

ct_bulletin = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(bulletin)
ct_flag = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(flag)

with open("output.txt", "w") as f:
    f.write("bulletin (plaintext, posted publicly):\n")
    f.write(bulletin.decode() + "\n\n")
    f.write(f"ct_bulletin = {ct_bulletin.hex()}\n")
    f.write(f"ct_flag = {ct_flag.hex()}\n")
```

`output.txt`
```!
bulletin (plaintext, posted publicly):
BULLETIN: This week's safety reminders from the helpdesk. Lock your screen when you walk away. Do not reuse passwords. And for the love of all that is good, never reuse a nonce with a stream cipher -- that's basically a two-time pad, and a two-time pad is no pad at all.

ct_bulletin = c359ca6adeff5a2d9f1ce2a05cfcc36ca21dd8a01c9cbfafac37c976d1f23f9bae381b0619b86e3a476ed1d70b51e450a501575905495e6a7c49e7b14fbe1cb65d0b5058579cbc1210875ae41a6d1cc717450d395d706c98d2a5f3c73cc34f277dfd4a86d9ec5c6af372b357c459a05f918bcfd1f9da44f94fa72de54fbad436f1ae6805c56233ffeaf17b0e34f6fe9cb398712dae0fd99a07c24537c36d365742dc46f2b14d2b447c7817b04b3d33c41c1fe376a17e404035dbcf43b748b76f897fe0e52efb726466a469d4a4a99724ffd8f025a2f215cd4f9b4f2b5cfe177d44a777236bd0c696b24054416553bf57423c2a23ac9e7abb33890a08f530f355bd35e6214e5653be9e1bf92f199d
ct_flag = f67ee345f0d067149563c2f958bcbc6bf31cecea5ecfb8faa161ce509fb32cc5b509185334fb3b286a31daa80c4df81cfe19
```

Provides you two ciphertexts, encrypted with same key and nonce.

### Solve

Like OFB mode, CRT mode generates a keystream and xor it with plaintext. Detail can be found in [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)).
Same key and nonce means same keystream.

$ct_{bulletin} = pt_{bulletin} \oplus keystram$
$ct_{flag} = pt_{flag} \oplus keystram$
$keystram = pt_{bulletin} \oplus ct_{bulletin}$

`solve.py`
```python
from Crypto.Util.number import long_to_bytes

bulletin = (
    b"BULLETIN: This week's safety reminders from the helpdesk. "
    b"Lock your screen when you walk away. Do not reuse passwords. "
    b"And for the love of all that is good, never reuse a nonce with "
    b"a stream cipher -- that's basically a two-time pad, and a "
    b"two-time pad is no pad at all."
)


ct_bulletin = 0xc359ca6adeff5a2d9f1ce2a05cfcc36ca21dd8a01c9cbfafac37c976d1f23f9bae381b0619b86e3a476ed1d70b51e450a501575905495e6a7c49e7b14fbe1cb65d0b5058579cbc1210875ae41a6d1cc717450d395d706c98d2a5f3c73cc34f277dfd4a86d9ec5c6af372b357c459a05f918bcfd1f9da44f94fa72de54fbad436f1ae6805c56233ffeaf17b0e34f6fe9cb398712dae0fd99a07c24537c36d365742dc46f2b14d2b447c7817b04b3d33c41c1fe376a17e404035dbcf43b748b76f897fe0e52efb726466a469d4a4a99724ffd8f025a2f215cd4f9b4f2b5cfe177d44a777236bd0c696b24054416553bf57423c2a23ac9e7abb33890a08f530f355bd35e6214e5653be9e1bf92f199d
ct_flag = 0xf67ee345f0d067149563c2f958bcbc6bf31cecea5ecfb8faa161ce509fb32cc5b509185334fb3b286a31daa80c4df81cfe19

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key))


ct_bulletin_bytes = long_to_bytes(ct_bulletin)
ct_flag_bytes = long_to_bytes(ct_flag)

flag = xor(xor(ct_bulletin_bytes, ct_flag_bytes), bulletin)
print(flag.decode())

```

## crypto/Bounding

### Challenge

```python
"""
Out on the red-dirt plains of Z_p*, an old bushman keeps two kangaroos.

  - Tame Roo bounds predictably from a known paddock.
  - Wild Roo was sighted somewhere downrange, and hops only a modest number
    of times before bedding down for the night.

The bushman refuses to say where Wild Roo started, but he'll swear on his
akubra that she hopped no more than MAX_HOPS times from the front gate.

He left his flag in the pouch of Wild Roo, encrypted to her silhouette.
"""

from Crypto.Util.number import getPrime, bytes_to_long, isPrime
import secrets


def safe_prime(bits):
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            return p, q


p, q = safe_prime(1024)

# the paddock's front gate: a generator of the order-q subgroup
while True:
    h = secrets.randbelow(p - 3) + 2
    g = pow(h, 2, p)
    if g != 1 and pow(g, q, p) == 1:
        break

# Wild Roo hops no more than this many times before turning in
MAX_HOPS = 1 << 44

# the hidden hop count
hops = secrets.randbelow(MAX_HOPS)

# where Wild Roo was last seen (her silhouette on the horizon)
silhouette = pow(g, hops, p)

# ElGamal-wrap the flag to Wild Roo's silhouette
flag = open("flag.txt", "rb").read().strip()
m = bytes_to_long(flag)
assert m < p

k = secrets.randbelow(q - 1) + 1
c1 = pow(g, k, p)
c2 = (m * pow(silhouette, k, p)) % p

with open("output.txt", "w") as f:
    f.write(f"p = {p}\n")
    f.write(f"g = {g}\n")
    f.write(f"MAX_HOPS = {MAX_HOPS}\n")
    f.write(f"silhouette = {silhouette}\n")
    f.write(f"c1 = {c1}\n")
    f.write(f"c2 = {c2}\n")


```

In short

$MAXHOPS=2^{44}$
$0 < h < MAXHOPS$
$silhouette=g^h\pmod p$
$k$ is secret.
$c_1 = g^k\pmod p$
$c_2 = m (silhouette)^k\pmod p$

Publish $p$, $q = (p-1)/2$ ,$g$, $MAXHOPS$, $silhouette$, $c1$, $c2$.

### Solve

If we can know $h$, then
$c_1^h = (g^k)^h = (g^h)^k = (silhouette)^k\pmod p$
$c_2c_1^{-h} = m (silhouette)^k(silhouette)^{-h} = m$

Fortunately, discrete log with bound $2^{44}$ can be computed efficiently. Sagemath provides parameter for bounds.
`hops = discrete_log(silhouette, g, bounds=(0, MAX_HOPS))`

solve.sage
```python
p = 166098514875595764654541504640396591045468899662086332329175858383529503832832841710504024371237723420984885135954468730357502745199674429893400929639866980448275459565414944974923657748962593798140937580687043237764380152923499409513037496572226986942036496113991128163914176355316399962782354947855034472339
g = 37428300087103233903345371968292747702308747851415083574680390249302279741003976715244778367655841934093781896953734487855356267068901703246648246503033574114259220509587198842809075756035977158021110654827184972478685429451268076768422447246174197462323642755391799873569801477331388504105427505206806670818
MAX_HOPS = 17592186044416
silhouette = 158073588727843300752732177211700938957418312383199126598045954956415534704861904084852032925892060883987033440648550136869668886384938078256290567141571186868256235939124744873703616854146143586632186370135236616624340898269150657908610992009796012007155251598415465908411184695276357103673048035444156836200
c1 = 124884449585047814054730447364859633843176589614423075012368716199646092521943838656802879751469914541933301392544006863815590285002121245932970019665684638253737652738687228580238012086899519444384228330390276649857735549344601882317959470420969963555914085366740734959244388986005529479242598696809707003592
c2 = 19438747884882024925064418136246700824573285789263411602837043287995164864126603919483842830578199005191924186927055121526370884077001674631043665273723304307860827109553014691584889824039727575853685303045137132928944495482354802889883355199624372544072513316083944177786670543307832021164031598754972224101


silhouette = Mod(silhouette,p)
g = Mod(g,p)

hops = discrete_log(silhouette, g, bounds=(0, MAX_HOPS))

m = Mod(c2, p) * Mod(c1, p)**(-hops)
print(m.to_bytes('big').strip(b'\x00'))

```

Flag: ||`wreck{b0und_4nd_r3b0und_th3_w1ld_r00_h0ps_h0m3}`||

## crypto/No Hash No Cash

### Challenge

`chall.py`
```python
#!/usr/local/bin/python3

from pathlib import Path
from secrets import randbelow


P = 11719074539505701570179551256761475579474630788098935157186366782163497511838277919152843883183287276995046555100101944094983110257847476121069350632264323
G = 2
FLAG = Path(__file__).with_name("flag.txt").read_text().strip()


def sign(secret_key, message):
    k = randbelow(P - 2) + 1
    r = pow(G, k, P)
    e = (r + message) % (P - 1)
    s = (k - secret_key * e) % (P - 1)
    return r, s


def verify(public_key, message, r, s): 
    if not (0 <= message < P - 1): 
        return False
    if not (1 <= r < P): 
        return False
    if not (0 <= s < P - 1): 
        return False
    e = (r + message) % (P - 1)
    return pow(G, s, P) == (r * pow(public_key, -e, P)) % P 


def read_int(prompt):
    print(prompt, end="", flush=True)
    return int(input().strip())


def main():
    secret_key = randbelow(P - 2) + 1 
    public_key = pow(G, secret_key, P)
    signed_messages = set()

    print("Welcome to my hashless signature service.")
    print("The public parameters are:")
    print(f"p = {P}")
    print(f"g = {G}")
    print(f"h = {public_key}")
    print()
    print("You may request 3 signatures on messages modulo p - 1.")

    for index in range(3):
        message = read_int(f"message #{index + 1} = ") % (P - 1)
        signed_messages.add(message)
        r, s = sign(secret_key, message)
        print(f"r{index + 1} = {r}")
        print(f"s{index + 1} = {s}")

    print()
    print("Now give me a valid signature on a fresh message.")
```

Using algorithm similar to [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm), server signs 3 messages for you, and you need to forge a signature that haven't been queried before.

### Solve

There are several differences between textbook DSA, but the most important one is that the message isn't hashed before calculation.

As a result, we can have full control on verification.
```python
    e = (r + message) % (P - 1)
    return pow(G,    s,        P) == (r * pow(public_key, -e, P)) % P
               ^     ^         ^      ^         ^          ^ 
            known  control   known  control   known       control
```

1. set $s = 0$, LHS becomes $1$
2. set $e$ to be a random value
3. set $r = h^{e}\pmod P$
4. set $message = e-r \pmod P$
5. check if $message$ is queried before, if yes, back to step 2.
6. send $(message, r, s)$ to server.

### 

`solve.py`
```python
from pwn import *
import subprocess
from random import randint

P = 11719074539505701570179551256761475579474630788098935157186366782163497511838277919152843883183287276995046555100101944094983110257847476121069350632264323
N = P - 1

client = remote("challs.wreckctf.com", 34502)

# Solve PoW
client.recvuntil(b"proof of work:\n")
pow_cmd = client.recvline().decode().strip()
client.recvuntil(b"solution:")
pow_solution = subprocess.check_output(pow_cmd, shell=True).strip()
client.sendline(pow_solution)


client.recvuntil(b"h = ")
h = int(client.recvline().strip())

signed = set()

# Sign messages 0, 1, and 2, result doesn't matter
for i in range(3):
    msg = i
    signed.add(msg)
    client.recvuntil(f"message #{i+1} = ".encode())
    client.sendline(str(msg).encode())
    client.recvuntil(f"r{i+1} = ".encode())
    client.recvline()
    client.recvuntil(f"s{i+1} = ".encode())
    client.recvline()

while True:
    s = 0
    e = randint(0, P - 1)
    r = pow(h, e, P)
    m = (e - r) % N
    if m not in signed:
        break

client.recvuntil(b"m = ")
client.sendline(str(m).encode())
client.recvuntil(b"r = ")
client.sendline(str(r).encode())
client.recvuntil(b"s = ")
client.sendline(str(s).encode())

client.interactive()
```

Flag: ||`wreck{dont_let_the_attacker_choose_the_challenge}`||

## crypto/skissue

### Challenge

`gen.py`
```python
from Crypto.Util.number import getPrime, bytes_to_long

bits = 1024
p = getPrime(bits)
q = getPrime(bits)
n = p * q
e = 65537

flag = open("flag.txt", "rb").read().strip()
m = bytes_to_long(flag)
c = pow(m, e, n)

print("p =", p)
print("q =", q)
print("n =", n)
print("e =", e)
print("c =", c)

with open("output.txt", "w") as f:
    f.write(f"n = {n}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {c}\n")
```

`output`
```!
n = 16560990740876422657409167351560243158175439270056388128657064439010227173912633679484940694811101957435847712501477158650768021546159765658445946717688951151905288381665394928260103317265224456472539960621935974617518379915381553301187366715192776682242805015724690041167254291708364800313210708251033443426845989545947222062545475420410535729391143390110372576899569469857880307485489295846784650997113357898627275734525131761392198566647858791494694971866301847273169349167659852729103190173112484307956280089935134790560073320935350753818936154379605479991466676687428072471167461790224226544737592609278296792717
e = 65537
c = 7208544918863509582735804917344804468518362825334386292610111640656312187430936946554093996743306475763881335697591498078161189710348998089325554364679509073133579075113450899969243189671651152099850995953381674204168733023818152588122038903707434129744691355001387278076026121944177142863838196657338886465882347294466222920708903811102639488581991411103320660351240113725040252819583351345562257052637139594748087858602282204002768973096193676014252271791707876422966143249590989834081745863624188741068643659846406141777961635055436016698295873237835090505285561213294452276478482155671351551665541767699418719944

```

### Solve

A textbook-RSA that doesn't seem to have any problem.
But the factors of $n$ are listed on [factordb](https://factordb.com/index.php?query=16560990740876422657409167351560243158175439270056388128657064439010227173912633679484940694811101957435847712501477158650768021546159765658445946717688951151905288381665394928260103317265224456472539960621935974617518379915381553301187366715192776682242805015724690041167254291708364800313210708251033443426845989545947222062545475420410535729391143390110372576899569469857880307485489295846784650997113357898627275734525131761392198566647858791494694971866301847273169349167659852729103190173112484307956280089935134790560073320935350753818936154379605479991466676687428072471167461790224226544737592609278296792717).

![image](https://hackmd.io/_uploads/rkeDSjHpWl.png)

Use this result to decrypt the ciphertext.

```python
# From factorDB
p = 124248059274385704319808025823012511701152709310788421738952371015145624337000849416139372935008360647240481464037822548998006591513049022158857606191398255594729458887356510988908323917610052483830445732506432894924707813555728788601959337767116345411235231323904055942982034770599767650463631047167614494127

n = 16560990740876422657409167351560243158175439270056388128657064439010227173912633679484940694811101957435847712501477158650768021546159765658445946717688951151905288381665394928260103317265224456472539960621935974617518379915381553301187366715192776682242805015724690041167254291708364800313210708251033443426845989545947222062545475420410535729391143390110372576899569469857880307485489295846784650997113357898627275734525131761392198566647858791494694971866301847273169349167659852729103190173112484307956280089935134790560073320935350753818936154379605479991466676687428072471167461790224226544737592609278296792717
e = 65537
c = 7208544918863509582735804917344804468518362825334386292610111640656312187430936946554093996743306475763881335697591498078161189710348998089325554364679509073133579075113450899969243189671651152099850995953381674204168733023818152588122038903707434129744691355001387278076026121944177142863838196657338886465882347294466222920708903811102639488581991411103320660351240113725040252819583351345562257052637139594748087858602282204002768973096193676014252271791707876422966143249590989834081745863624188741068643659846406141777961635055436016698295873237835090505285561213294452276478482155671351551665541767699418719944

assert n%p == 0
q = n//p
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]).decode())

```

Flag: ||`wreck{n0_sk1ll_1ssu3}`||

