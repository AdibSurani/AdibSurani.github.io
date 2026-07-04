---
title: "Author's write-up for apbq-rsa-iv"
categories:
  - writeup
tags:
  - SekaiCTF
  - crypto
toc: true
toc_sticky: true
---

This is the official write-up for the crypto challenge _apbq-rsa-iv_ from SekaiCTF 2026, written by yours truly.

<!--more-->

It's the latest instalment in the _apbq-rsa_ series, based on joseph's apbq-rsa-ii from DownUnderCTF 2023, with a very minimal diff.

```diff
-    a, b = randint(0, 2**312), randint(0, 2**312)
+    a, b = randint(0, 4**312), randint(0, 4**312)
```

This is the fourth challenge in the series, and each instalment has incremented the base:

| Challenge | CTF | Author | Bound |
| --- | --- | --- | --- |
| [apbq-rsa-ii](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/apbq-rsa-ii) | DownUnderCTF 2023 | joseph | $2^{312}$ |
| [apbq-rsa-iii](https://imaginaryctf.org/ArchivedChallenges/71) | ImaginaryCTF Round 59 | Neobeo | $3^{312}$ |
| apbq-rsa-iv | SekaiCTF 2026 | Neobeo | $4^{312}$ |

This final version is about as hard as it gets, but 10 teams managed to solve it during the competition. Congratulations to them (slopped or not)!

# The challenge

{::options parse_block_html="true" /}
<style>
details {
    background-color: #f4f4f5;
    padding: .5rem 1rem;
    margin-bottom: .5rem;
    border-radius: 4px;
}
</style>

<details><summary markdown="span">Code for the challenge</summary>

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(3):
    a, b = randint(0, 4**312), randint(0, 4**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```
</details>

<details><summary markdown="span">Output</summary>

```
n = 14999853502053319423177058744221961325834010847678005650848398429465000177140714196548148163337804416021374304634949441426248580403103555437026478929190722038490304981753636704180827512199831461832922688976201190837767205719465583763780813282929971684255380122478746337344012884510287043648239025146943139770759285350904634371574155585163484628015601322749120894631751396028253790888810238633427403492450330068078846135717819188006869084181968212553909046171001145518649028552848071756770253813553246903033362383065552519421028172300841616323846025346701078634029291848843603454769598945666459490997524707271990596543
c = 4842456813206744639215822112251201329733732108133819315232654780513216078743525148300527476668433418306199581962731135281577724403631081759430211576597930102127958055772489318280352507058623962349936621745379119578446462282985031447559734942794566491432740620465551308811827761604137839752888378985855740568997772023228990671689003303463565739087129463953005055685089755272190485629749577509375756559176926609680892078217484945028018066421049575711038063621844737131941961191175340753620026142512918863674283674573267438210993185981539514081784698587589295127382598872596432924017993500843329511734518698670686102195
hints = [5375304907678477104967708980595850172904570744844840479112465973975716018640406062518012600007461414423566032044022466751576573355958378137085799506211264068963278482266668297989383477851021303711380095372703399364129909004445809487050651296083860343265402984109663537222380041605494345079182805110381505697275575688858695302528055019284285158822170010834400226336858184306845968429425252696660677606844017246870062671467660394469171523543248204360744912516010559859868810644811887402848827561223, 13971157658006406068140088711197814259141302748988767182314964521198606279042495002874210789918142428045931596453392823687808652907740269158134107135884094906016042996074927396903646563426915461403506317922061776736434298185849223204346317547586927117840152854744975205236117375896408595189997911288539505874399722244241073096889372775532677882355311816172750224388652112218259134499412971462867479492883781954131256437047468550964462049767181768318709005275401621875710674623689941210245781870099, 11973881421056283464616362728709698271314884408110648616330436789505930054382536678505721685707765982554863816643405134314276996082728393678221599876021680882446167608847619080643915396888875187360719194200995925675162335840978547541701213443038476555710295706596532967348319145464089501644085811324748296480711770928663729683996760638798139351941320687552108305362036835907251463878950680657020392548261237769318929638022352941368564224199621775977493122486554785508581089360519540429611052802727]
```
</details>
{::options parse_block_html="false" /}

Basically, we are given $n=pq$ and three hints

$$
h_i=a_ip+b_iq,\qquad 0\le a_i,b_i<4^{312}=2^{624}.
$$

# The intended solution

The reader is expected to be familiar with Coppersmith constructions in general; here I will discuss the specific polynomials and shifts I used to solve this challenge.

The key trick is to introduce the "conjugate" values

$$
u_i=a_ip-b_iq.
$$

These are unknown, but bounded by the hints $ \|u_i\| \le h_i$.

Define a system with three fundamental polynomials of $(X, Y, Z)$:

$$
\begin{align*}
f_0 &= h_2 X - h_0 Z, \\
f_1 &= h_2 Y - h_1 Z, \\
f_2 &= Z^2 - h_2^2,
\end{align*}
$$

and we would like to solve this system of equations modulo $n$. So we get a trivariate small-root problem with bounds

$$
|X|\le h_0,\qquad |Y|\le h_1,\qquad |Z|\le h_2.
$$

It is easily checked that $\pm(h_0,h_1,h_2)$ and $\pm(u_0,u_1,u_2)$ are roots of the system modulo $n$.


## The lattice

We construct the Coppersmith lattice using the shifts

$$
g_{x,y,z}(X,Y,Z) = f_0^x f_1^y f_2^{\lfloor z/2\rfloor} Z^{z-\lfloor z/2\rfloor},
$$

where $x+y+z$ is even, up to some fixed maximum sum.

It is clear that every polynomial $g_{x,y,z}$ is even, and admits the aforementioned roots modulo $n^{x+y+\lfloor z/2\rfloor}$.

The number of triples with $x+y+z=d$ is $\binom{d+2}{2}$. Using all shifts with $d=0,2,4,6,8,10$, this gives a lattice of size

$$
\binom22+\binom42+\binom62+\binom82+\binom{10}2+\binom{12}2 = 161,
$$

and it is able to solve the system up to $a_i,b_i<2^{625.77}$, which gives us just enough margin to solve this challenge. We leave it up to reader to verify this bound (and also that the asymptotic Coppersmith bound is $2^{682.66}$ as we take $d$ arbitrarily large).

The rest of the process carries out the same way as any multivariate Coppersmith challenge -- grab a few short polynomials and Groebner basis to find all small roots over $\mathbb{Q}$. There should be exactly four roots, and we can use them to factorise $n$ and obtain the flag.

## Optimisation to avoid GB

The four roots above actually correspond to a 2-dimensional kernel of the lattice (the sign is ignored because the polynomials are even). Additionally, we already know a vector in the kernel corresponding to $(h_0,h_1,h_2)$, so we can just solve for the difference between these two vectors. This is equivalent to just chopping off the constant coefficient in each polynomial, and we are left with a 160x160 lattice. This is exactly how I implemented it in the solve script below, and as an added bonus we can just take the kernel directly without having to do any Groebner basis calculations.

# Solve script

{::options parse_block_html="true" /}
<details><summary markdown="span">Full solve script</summary>

```py
n, c, hints = ...

F.<X,Y,Z> = ZZ[]
f = vector([X - hints[0]/hints[2]%n * Z, Y - hints[1]/hints[2]%n * Z, Z^2 - hints[2]^2]) / n
arr = [f[0]^x * f[1]^y * f[2]^(z//2) * Z^(z%2) for i in range(5) for x,y,z in IntegerVectors(2*i+2, 3)]

CM, mon = Sequence(g - g(0,0,0) for g in arr).coefficients_monomials(sparse=False)
lll = (CM * diagonal_matrix(mon(*hints), sparse=False)).LLL(algorithm="flatter")

v = lll.solve_right(vector([0]*(len(mon)-1)+[1]))
p = gcd(n, 1 + sqrt(v[-7]/v[-1]-1)%n)
print(f'{p = }')
print(pow(c, pow(65537,-1,(p-1)*(n//p-1)), n).to_bytes(256).strip(b'\0'))
# p = 121107345457368243970384538911139273807940467122121755618639023203729738715244778100171925943768321521576165407807120259194271231531509469590709002597084050238492860886037142905314502902270200274559211956784275022654996301298060002838736330645710076001812263552133903691591470901086788237685266147302909554899
# b'SEKAI{rural_ambiance_at_sixes_and_sevens_by_6_or_7_answer_is_two_words_of_lengths_six_and_seven}'
```
</details>
{::options parse_block_html="false" /}
