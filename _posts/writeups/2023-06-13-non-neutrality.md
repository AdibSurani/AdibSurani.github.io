---
title: "Author's write-up for Non-neutrality"
categories:
  - writeup
tags:
  - SEETF
  - crypto
---

This is the official write-up for the crypto challenge Non-neutrality from SEETF23, written by yours truly.

<!--more-->

{::options parse_block_html="true" /}
<details><summary markdown="span">Code for non-neutrality.py</summary>
```python
from secrets import randbits
from Crypto.Util.number import bytes_to_long
import os

flag = os.environ.get('FLAG', 'SEE{not_the_real_flag}').encode()

# get a one-time-pad in which not exactly half the bits are set
def get_xorpad(bitlength):
    xorpad = randbits(bitlength)
    return xorpad if bin(xorpad).count('1') != bitlength // 2 else get_xorpad(bitlength)

def leak_encrypted_flag():
    return bytes_to_long(flag) ^ get_xorpad(len(flag) * 8)

# I managed to leak the encrypted flag a lot of times
if __name__ == '__main__':
    for _ in range(2**16):
        print(leak_encrypted_flag())
```
</details>
{::options parse_block_html="false" /}

The code, at only 18 lines, is fairly straightforward to follow. You encrypt a flag 65536 times, each time with a different xorpad in which not exactly half the bits are set. From looking at the output file `nn_out.txt`, we can see that the flag is 272 bits long, so each xorpad has a hamming weight not equal to 136.

## High-level Idea

So the high-level idea is the following:
1. First we remove all rows that were xored with an odd-parity xorpad, as they add nothing but noise.
2. Next we calculate the probability of each unknown bit position being set, which we do as follows:
   - For each bit position, go through each row and calculate (from that row alone) the probability that the bit is set, using the fact that we have some known bits
   - Combine these over all rows to get a global estimate of the probability
3. Go through all these probabilities and pick the ones that we are most confident. Either some threshold or some fixed number -- we choose to pick ten at a time. Repeat until we have assigned all bits of the flag.

## Details (Step 1)

First we note that exactly half of all $2^{272}$ possible xorpads have even parity. But also, $\binom{272}{136}$ of these have hamming weight 136, which represents 4.83% of those xorpads. In other words, we can break down the percentages as follows:

* Odd hamming weight: 50%
* Even hamming weight not equal to 136: 45.2%
* Hamming weight exactly 136: 4.83%

Since the latter is eliminated, we expect there to be more odd-weight messages among our 65536 messages, with a ratio of about 10:9. That is exactly what we find:

```python
from collections import Counter
arr = [int(x) for x in open('nn_out.txt').readlines()]
print(Counter(bin(x).count('1')%2 for x in arr))
# Counter({1: 34422, 0: 31114})
```
As we can see, there are more messages of odd weight, so our flag must have even weight.

Why is this important? This is because the odd-weight xorpads give us no additional information and only add noise to the system. Which is possibly fine if we had a million messages, but 65536 is very tight so we should remove as much noise as we can.

## Details (Step 2)

Let's do some combinatorics!

Denote by $f(n,k)$ the number of $n$-bit values whose hamming weight has the same parity as $k$ but is not equal to $k$. For example, $f(5,3)=6$ because it can take six possible values:
`00001`, `00010`, `00100`, `01000`, `10000`, and `11111`.

It is left an exercise to the reader to prove that $f(n,k) = 2^{n-1} - \binom{n}{k}$.

Let's look at a small example: suppose we have an 8-bit xorpad with even hamming weight not equal to 4. And suppose we know that it begins with `100`. Then what is the probability that any of the other 5 bits is set?

This is actually the same enumeration above: if we focus on say the last bit (wlog) we can see that there are four 0s and two 1s, so there is a 1/3 probability of it being set. This is also equivalent to saying $f(4,3)=4$ and $f(4,2)=2$. In other words, we can derive the probability from the ratio $f(n-1,k):f(n-1,k-1)$.

In fact, this motivates a different representation of likelihood, which is to use the ratios of the sizes of possible universes. Instead of using the probability of 1/3, we will work with the ratio of 4:2. This allows us to easily multiply the different rows, e.g. (4:2) * (100:10) = (400:20). We can think of this as "there are 400 universes in which it's a 0, and 20 universes in which it's a 1".

To reiterate, the plan is as follows. For each row, we know some bits of the xorpad, which as above allows us to learn the probability of the unknown bits being set. If we have $n$ unknown bits and know that the hamming weight cannot be $k$, then we have here the ratio $f(n-1,k):f(n-1,k-1)$. And then we multiply this over all the rows. As an implementation detail, we use logs so we can add and subtract instead of multiplying.

## Details (Step 3)

That's about it really. For each bit position we have a ratio $r$, and the larger the magnitude of $\log(r)$ the more confident we are of our prediction. So we just take the 10 best ratios, insert it into the flag, and repeat.

## Putting it all together

We put all of the above into the following python script:
```python
from collections import Counter
from pwn import bits, unbits
from scipy.special import binom
import numpy as np

# determine the parity of our flag
arr = [int(x) for x in open('nn_out.txt').readlines()]
print(Counter(bin(x).count('1')%2 for x in arr))
# Counter({1: 34422, 0: 31114})
# This means the flag has an even number of set bits

# set up array with our encrypted bits
arr = [x for x in arr if bin(x).count('1')%2 == 0]
LEN = max(arr).bit_length()
assert LEN == 272
arrbits = np.array([[int(a) for a in f'{x:0272b}'] for x in arr])

# set up array with our guesses for the flag
flag = 'SEE{?????????????????????????????}'
flagbits = np.array(bits(flag.encode()))

# set up array of which positions are known. it's ASCII so every MSBit is set
known = np.array([False] * 272)
for i, c in enumerate(flag):
    if c == '?':
        known[8*i] = True
    else:
        known[8*i:8*i+8] = True
        
# this is the same function defined above, but in the log space
def f(n,x):
    return np.log(2.0**(n-1) - binom(n,x))
        
while n := sum(~known):

    # calculate our probabilities! this has a scale of -inf to inf rather than the usual 0 to 1
    k = 136 - np.count_nonzero(known * (arrbits != flagbits), -1)
    probs = (f(n-1, k) - f(n-1, k-1)) @ (2 * arrbits - 1)

    # out of all the unknown bits, get the 10 with the best probability
    inds = np.nonzero(~known)[0]
    inds = inds[np.argsort(-abs(probs[inds]))[:10]]

    # set these flag bits to the corresponding sign 
    flagbits[inds] = probs[inds] > 0
    known[inds] = True

    # print our best estimate of the flag
    print(unbits(np.where(known, flagbits, probs > 0)))
```

We get the following output:

```
b'SEE{_?M?eawEll-\x1f3~a\x7fsx]C\x15asY"~E[\x1e}'
b'SEE{_?Mo|a7ell-\x1f1}c~bhYC\x1di3\\`xE[\x0e}'
b'SEE{W~Ly}Ewdll-\x1f1Ma~chyC\x1di3\x19b|EY\x0e}'
b'SEE{W~Xy}E7`ll)\x1f1Ma~biYG\x15i3]#|EY\x0f}'
b'SEE{W^xy}Gwdll9\x1f1ma~chYG\x1dI3}#|EQ\x0f}'
b'SEE{W^|ymGwdll)\x1f1oa~ciYC\x1fI1]\x03xEY\x0f}'
b'SEE{W^ly|Ewdll)\x1f1oq~ci}C\x1fI1}#leY\x0f}'
b'SEE{W^li|Ewdll)_1\x7fq~ci]C\x1fI1~"la[\x0f}'
b'SEE{W\\|i}E\x7f`ll)_1\x7fq\x7fbi]C\x1fI1\x7fbld[\x0e}'
b'SEE{W\\}iuev`lly_!\x7fy_byMC\x1fIs{ble[\x0f}'
b'SEE{WM|iuev`lly_a\x7fy^biys_Hs_"me_\x1f}'
b'SEE{WO|kuewally_!\x7fy_biis_hs_"ie_\x1f}'
b'SEE{_Oliuevally_a\x7fy_biis_iq_"me_\x1f}'
b'SEE{_Olitevally_!oy_biis_is_bad_\x7f}'
b'SEE{_Olitevally_any_biis_is_bqd_\x7f}'
b'SEE{_Olitevally_any_bias_is_bad__}'
b'SEE{__litevally_any_bias_is_bad__}'
b'SEE{__litevally_any_bias_is_bad__}'
```

In this case we end with `b'SEE{__litevally_any_bias_is_bad__}'` which has one bit of error. Depending on the exact parameters chosen, you might have more errors, but e.g. if you make out the phrase `is_bad` or something you can put it in the known plaintext and retry from the start.

The intended flag is `SEE{__literally_any_bias_is_bad__}`.