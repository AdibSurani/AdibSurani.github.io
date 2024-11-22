---
title: "Write-up for crypto/The Door to the Xord"
categories:
  - writeup
tags:
  - LITCTF
  - crypto
---

This is a write-up for an easy-medium crypto challenge written by CodeTiger for [LITCTF 2023](https://lit.lhsmathcs.org/ctf) called The Door to the Xord.

<!--more-->

(It could be because I've seen a similar challenge before, but I pretty much knew what to do from the get-go.)

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Brief intro about myself</summary>
    
I am [Neobeo](https://ctftime.org/user/126534), and I play as a crypto main for [Social Engineering Experts](https://ctftime.org/team/151372). We weren't planning to tryhard this competition, and in fact finished nowhere near the top at 52nd.

![](/assets/images/yourdidit-f1418173-5825-40c8-b682-98e419027748.png)

    
For the most part, I was only really interested at the unblooded crypto, so that was all I looked at. And that was only about 18 hours after the competition started.

There were three unblooded crypto at that time, and by some miracle I managed to blood all of them. They were:
- **Climbing Snowdon** (7 solves / 388 points) -- guessy non-crypto challenge, not worth discussing[^snowdon]
- **Your Did It!** (1 solve / 481 points) -- an insanely difficult challenge that I wrote up about [here](/2023/your-did-it/)
- **The Door to the Xord** (1 solve / 481 points) -- which I will be discussing in this write-up
    
[^snowdon]: Ok, I lied. [Here's my write-up.](/2023/climbing-snowdon/)
</details>
{::options parse_block_html="false" /}

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Official challenge statement</summary>
    
*crypto/The Door to the Xord* by *w0152*

> You must solve this puzzle to meet the Xord, the Xor Lord. > Wrap your flag with LITCTF{}.
> Connect with `nc litctf.org 31771`
    
Attachment: yourdidit.py

```python
#!/usr/bin/env python3
import random
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl

with open("flag.txt", "rb") as f:
	x = f.read().strip()

assert len(x) == 32

def xor(x, y):
	# the better way to xor strings
	# (just in case they have different length, one will be treated as if it was rjusted with \0s)
	return ltb(btl(x)^btl(y))

while True:
	input("Press enter to get some gibberish: ")
	blen = len(x)*8

	val = random.getrandbits(blen)
	print(xor(x, ltb(val)).hex())
```
</details>
{::options parse_block_html="false" /}

## High-level challenge description

The setup is extremely simple and minimalistic[^mini]. You have a 32-byte flag which can be XORed with `random.getrandbits(256)` as many times as you want (by pressing enter). And that's it.

[^mini]: I get to say this because my challenges also tend to have very few lines. Do check out my [one-liner crypto challenge](/2023/onelinecrypto/)!

## The exploit itself

[One-time pads](https://en.wikipedia.org/wiki/One-time_pad) are typically [information-theoretically secure](https://en.wikipedia.org/wiki/Information-theoretic_security), as long as the pad itself is random (in a cryptographic sense). However, we are using python's `random` module, which uses the Mersenne Twister. This is a PRNG that is surprisingly easy to break!

There are various websites that detail how MT19937 is implemented in python, such as [here](https://github.com/anneouyang/MT19937) and [here](https://www.schutzwerk.com/en/blog/attacking-a-rng/), so I won't go into much detail here.

But the main key points we require for this exploit are:
1. MT19937 is entirely linear (so you can compose with XOR and it remains linear)
2. It has 19968[^19968] bits of state, which is usually represented as 624 32-bit words ($624 \times 32 = 19968$)

The usual way we do MT exploits is to know 624 consecutive 32-bit outputs, and then use these to predict other values going forwards or backwards. However, in this case we don't actually directly know any of the PRNG outputs, just the output XORed with the flag. This is what makes the challenge different to other typical MT challenges.

But once you understand that it's linear, none of the other detail matters, and we can just implement MT19937 in [Z3](https://en.wikipedia.org/wiki/Z3_Theorem_Prover).

So how many outputs do we need? Equivalently, how many unknown bits are there in the state as a whole? Well, the PRNG has 19968 bits of state (actually 19937, but let's err on the side of caution). And then the flag has another 256 bits (again, if we know it's ASCII then the most significant bits are unset which makes it $32 \times 7 = 224$). So we need $\frac{19968+256}{256}=79$ outputs.

## Solve script

So basically, the main thing is to implement the MT19937 PRNG in Z3 rather than direct python (namely a twist and a temper). That accounts for the 19968 bits. And then another 32 bits for the flag which we will represent as a `BitVec`.

The only other thing to take care is which way to concatenate the 32-bit outputs into the 256-bit value. Let's quickly test how this works.

```python
import random
random.seed(0)
print([hex(random.getrandbits(32)) for _ in range(8)])
random.seed(0)
print(hex(random.getrandbits(256)))
```

This prints the following:
```
['0xd82c07cd', '0x629f6fbe', '0xc2094cac', '0xe3e70682', '0x6baa9455', '0xa5d2f34', '0x42485e3a', '0xf728b4fa']
0xf728b4fa42485e3a0a5d2f346baa9455e3e70682c2094cac629f6fbed82c07cd
```

which indicates that it concatenates "backwards", so to speak.

So a single output (from pressing enter) is equivalent to getting eight consecutive 32-bit words from the PRNG, concatenating them in reverse, then XORing it with the flag. Simple!

The solve script is as follows:
```python
from pwn import *
from z3 import *

with remote('litctf.org', 31771) as sh:
    sh.sendlines([b'']*79)
    arr = [int(sh.readline().decode().split()[-1], 16) for _ in range(79)]
    
MT = [BitVec(f'm{i}', 32) for i in range(624)]
s = Solver()

def cache(x):
    tmp = Const(f'c{len(s.assertions())}', x.sort())
    s.add(tmp == x)
    return tmp

def temper(y):
    y ^= LShR(y, 11)
    y = cache(y ^ (y << 7) & 0x9D2C5680)
    y ^= cache((y << 15) & 0xEFC60000)
    return y ^ LShR(y, 18)
    
def getnext():
    x = Concat(Extract(31, 31, MT[0]), Extract(30, 0, MT[1]))
    y = If(x & 1 == 0, BitVecVal(0, 32), 0x9908B0DF)
    MT.append(cache(MT[397] ^ LShR(x, 1) ^ y))
    return temper(MT.pop(0))
    
flag = BitVec('flag', 256)
def getmsg():
    return Concat([getnext() for _ in range(8)][::-1]) ^ flag

s.add([getmsg() == z for z in arr])
assert s.check() == sat
print(s.model()[flag].as_long().to_bytes(32,'big'))
```

The `cache` does nothing from a purely logical/correctness point of view, but it helps to speed up the solver by "saving" intermediate values.

Anyway, the script runs in about 15 seconds, and prints out:
```
b'you_have_opened_xa_xoor_382d102f'
```

The flag is `LITCTF{you_have_opened_xa_xoor_382d102f}`.

[^19968]: Technically only 19937 bits are needed (thus the name), and you can fully determine the other 31 bits from the 19937.