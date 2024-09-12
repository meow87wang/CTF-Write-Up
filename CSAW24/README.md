# CSAW'24 Write UP

| Place    | Score |
| -------- | ----- |
| 255/1184 | 1058  |

Passed all Crypto challenges.

## Crypto

### Trapdoor

> RSA common divisor

We can obtain a common divisor of two public keys. Thus we can divide to public keys and get the private key.

```
csawctf{sowwy_W3_b0u9ht_a_l34ky_tr4pd00r!}
```

### HexHex

There are two lines which are not valid ASCII Hex string.

Based on the Challenge's title, Google "hex cipher", come out "twin hex cipher". 

> Twin hex cipher

```
csawctf{hex3d_i7_w3l7_innit_hehe}
```

### Diffusion Pop Quiz

In `anf_extractor.py`, change the following values to get the answer of the quiz.

```python3=
example = []  # Truth table
INPUT_BITS = 8 # Length of input in bits
OUTPUT_BITS = 8 # Length of output in bits
BIT = 7 # Which bit you want, count from right
```

```
csawctf{hopefu11y_+he_know1ed9e_diffu5ed_in+o_your_6r@in5}
```

### AES dif

Use `aes_simulator.py`, very straight forward.

```
csawctf{1_n0w_und3r5t4nd_435_d1ffu510n}
```

### CBC

CBC padding oracle attack.

There are 2400 bytes to decrypt, and the flag is not located at head neither tail.
So you need some time to get the flag.

```
csawctf{I_L0ST_TR4CK_0N_WH3R3_I_W4S_G01NG_W1TH_TH15}
```
