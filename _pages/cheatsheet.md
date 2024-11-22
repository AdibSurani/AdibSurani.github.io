---
permalink: /cheatsheet/
title: "Cheat Sheet"
---

This really needs to be updated. It's mostly a copy-and-paste of a previous post.

## Flatter
```python
def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    # if flatter is not available we can just return M.LLL() instead
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(ZZ, findall(b"-?\\d+",ret)))
```

## Half-gcd
[Romeo and Juliet](https://github.com/Social-Engineering-Experts/SEETF-2023-Public/blob/main/challs/crypto/romeo-and-juliet/solve/solve_romeo_and_juliet.py)
```python
def GCD(a, b):
    
    def HGCD(a, b):
        if 2 * b.degree() <= a.degree() or a.degree() == 1:
            return 1, 0, 0, 1
        m = a.degree() // 2
        a_top, a_bot = a.quo_rem(x**m)
        b_top, b_bot = b.quo_rem(x**m)
        R00, R01, R10, R11 = HGCD(a_top, b_top)
        c = R00 * a + R01 * b
        d = R10 * a + R11 * b
        q, e = c.quo_rem(d)
        d_top, d_bot = d.quo_rem(x**(m // 2))
        e_top, e_bot = e.quo_rem(x**(m // 2))
        S00, S01, S10, S11 = HGCD(d_top, e_top)
        RET00 = S01 * R00 + (S00 - q * S01) * R10
        RET01 = S01 * R01 + (S00 - q * S01) * R11
        RET10 = S11 * R00 + (S10 - q * S11) * R10
        RET11 = S11 * R01 + (S10 - q * S11) * R11
        return RET00, RET01, RET10, RET11

    q, r = a.quo_rem(b)
    if r == 0:
        return b
    R00, R01, R10, R11 = HGCD(a, b)
    c = R00 * a + R01 * b
    d = R10 * a + R11 * b
    if d == 0:
        return c.monic()
    q, r = c.quo_rem(d)
    if r == 0:
        return d
    return GCD(d, r)
```    

## Lattice enumeration with cpmpy
[onelinecrypto](https://demo.hedgedoc.org/2i2plevkRam_WpOetHVdUA)

```python
from sage.all import *
from cpmpy import *
import re

n = 13**37
empty = b'SEE{' + bytes(23) + b'}'
target = int.from_bytes(empty, 'big') * pow(256, -1, n)

m = matrix(24, 24)
m[0,0] = n
for i in range(22):
    m[i+1,i:i+2] = [[-256, 1]]
m[-1,0] = -target
m[-1,-1] = 2**256 # some arbitrarily large number

def disp():
    flag = bytes(x.value())[-8::-8].decode()
    print(flag, '<--- WIN' if re.fullmatch(r'\w+', flag) else '')

x = cpm_array(list(intvar(-99999, 99999, 23)) + [1]) @ m.LLL()[:,:-1]
Model([x >= 48, x <= 122]).solveAll(display=disp)
```

## Coppersmith hacks
[cig_solver (on Discord)](https://discord.com/channels/692694094111309866/744261335826563145/1153664561862422609)
```python
# solve xy+Ax+By+C=0 (mod N), with |x|,|y|<Δ and using m shifts
# m can be determined automatically if not provided
# follows this paper: https://www.iacr.org/archive/pkc2012/72930609/72930609.pdf
# only returns x because I am lazy
def solve_x(A, B, C, N, Δ, m=None):
    F,(x,y) = ZZ['x,y'].objgens()
    f = x*y + A*x + B*y + C
    
    if m is None:
        t = log(Δ,N)
        m = ceil((1-6*t)/(6*t-2))
        print(f'Automatically picked {m=}')
    
    def make_poly(i, j):
        f_pow = min(i, j)
        x_pow = max(0, i - j)
        y_pow = max(0, j - i)
        N_pow = m - f_pow
        return (f**f_pow * x**x_pow * y**y_pow * N**N_pow)(x = Δ*x, y = Δ*y)

    mat,c = Sequence([make_poly(i,j) for i in range(m+1) for j in range(m+1)]).coefficient_matrix(sparse=False)
    lll = flatter(mat) / diagonal_matrix(vector(c(x=Δ,y=Δ))) * c
    print('reduced', flush=True)
    
    hs = [F(p) for p in lll]
    for j in range(m+1):
        for i in range(j):
            for root,_ in hs[i].resultant(hs[j],y).univariate_polynomial().roots():
                return root
```

## MT19937
[The Door to the Xord](https://demo.hedgedoc.org/RBcnx5l3SvyAJUXYXwc3-A)

```python
from z3 import *
    
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
```

## Popular params for ECDSA
[secp256k1](https://asecuritysite.com/sage/sage_01)
```python
###### secp256k1
p256 = 2^256-2^32-977
a256 = 0
b256 = 7

## Base point
gx= 55066263022277343669578718895168534326250603453777594175500187360389116729240L
gy= 32670510020758816978083085130507043184471273380659243275938904335757337482424L

## Curve order
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337L
FF = GF(p256)
EC = EllipticCurve([FF(a256), FF(b256)])
EC.set_order(n)

## Base point
G = EC(FF(gx), FF(gy))
```

## Dlog for elliptic curves
[sagemath docs](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html)
```
sage: Q = 39*P; Q
(36*a + 32 : 5*a + 12 : 1)
sage: discrete_log(Q,P,P.order(),operation='+')
39
```

## Lee-Brickell ISD
[sagemath docs: ISD decode](https://doc.sagemath.org/html/en/reference/coding/sage/coding/information_set_decoder.html#sage.coding.information_set_decoder.InformationSetAlgorithm.decode)
```python
M = matrix(GF(2), [[1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0],\
C = codes.LinearCode(M)
from sage.coding.information_set_decoder import LeeBrickellISDAlgorithm
A = LeeBrickellISDAlgorithm(C, (2,2))
r = vector(GF(2), [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
A.decode(r)
```

## Berlekamp-Massey algorithm
[sagemath docs: BMA](https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/berlekamp_massey.html)
```
from sage.matrix.berlekamp_massey import berlekamp_massey
sage: berlekamp_massey([2,2,1,2,1,191,393,132])
x^4 - 36727/11711*x^3 + 34213/5019*x^2 + 7024942/35133*x - 335813/1673
```

## Length extension attack
If it's SHA1/SHA256/SHA512 we can use [hlextend](https://github.com/stephenbradshaw/hlextend).

Otherwise there's also [hash_extender](https://github.com/iagox86/hash_extender) which is a bit harder to use.

## AES-GCM (soon_haari loves these)

[@todo]