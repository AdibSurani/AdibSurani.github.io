---
title: "Write-up for crypto/Your Did It!"
categories:
  - writeup
tags:
  - LITCTF
  - crypto
---

This is a write-up for an insanely difficult crypto challenge written by CodeTiger for [LITCTF 2023](https://lit.lhsmathcs.org/ctf) called Your Did It!

<!--more-->

(At least, the way I solved it was insanely difficult. The intended solution does avoid a lot of the problems I ran into, but it has the problem of being highly non-trivial to notice in the first place.)

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Brief intro about myself</summary>
    
I am [Neobeo](https://ctftime.org/user/126534), and I play as a crypto main for [Social Engineering Experts](https://ctftime.org/team/151372). We weren't planning to tryhard this competition, and in fact finished nowhere near the top at 52nd.

![](/assets/images/yourdidit-f1418173-5825-40c8-b682-98e419027748.png)

    
For the most part, I was only really interested at the unblooded crypto, so that was all I looked at. And that was only about 18 hours after the competition started.

There were three unblooded crypto at that time, and by some miracle I managed to blood all of them. They were:
- **Climbing Snowdon** (7 solves / 388 points) -- guessy non-crypto challenge, not worth discussing[^snowdon]
- **The Door to the Xord** (1 solve / 481 points) -- an easy-medium challenge which I'm surprised had no other solves. I wrote up on it [here](/2023/door-to-the-xord/)
- **Your Did It!** (1 solve / 481 points) -- which I will be discussing in this write-up
    
[^snowdon]: Ok, I lied. [Here's my write-up.](/2023/climbing-snowdon/)
</details>
{::options parse_block_html="false" /}

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Official challenge statement</summary>
    
*crypto/Your Did It!* by *CodeTiger*

> UwU the Your Did It Star wants to see if Your can did this challenge. I've heard that even the yourdidit star's cipher is different because of how yourdidit it is! Can you break it?
> Connect with `nc litctf.org 31789`
> ![](/assets/images/yourdidit-50869edf-5c52-4925-a624-b82b59daec57.png)
    
Attachment: yourdidit.py
    
```py
#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import binascii

flag = open('flag.txt','rb').read().decode("utf-8");

class YourDidItRNG:
    def __init__(self,size):
        self.mask = (1 << size) - 1;
        self.mod = 79563462179368165893806602174110452857247538703309854535186209058002907146727;
        self.seed = 0;

    def infuseYourDidItPower(self,power,step):
        self.seed = (step * power) % self.mod;

    def next(self):
        self.seed = ((self.seed * 573462395956462432646177 + 7453298385394557473) % self.mod); # try converting these to text ;)
        return self.seed & self.mask;

    def yourdidit(self,goodjob):
        # Priming the your did it star power!
        for i in range(5 * 5):
            self.next();
        # It is known that the Your Did it star has 5 sides and 5 vertices. Thus, we must combine its powers 5 times for the ultimate Your Did It Star Power!
        YourSoDidIt = self.next() | self.next() | self.next() | self.next() | self.next();
        YourSoDidIt = ((YourSoDidIt & goodjob) ^ self.next()) & self.mask;
        return YourSoDidIt;

class YourDidItAESCipher:
    def __init__(self):
        self.BLOCK_SIZE = 16;
        self.key = get_random_bytes(self.BLOCK_SIZE);
        self.YourDidIt = YourDidItRNG(self.BLOCK_SIZE * 8);

    def encryptSingleBlock(self,block):
        assert(len(bytes.fromhex(block)) == self.BLOCK_SIZE);
        cipher = AES.new(self.key,AES.MODE_ECB);
        return cipher.encrypt(bytes.fromhex(block)).hex().zfill(32);

    def decryptSingleBlock(self,block):
        assert(len(bytes.fromhex(block)) == self.BLOCK_SIZE);
        cipher = AES.new(self.key,AES.MODE_ECB);
        return cipher.decrypt(bytes.fromhex(block)).hex().zfill(32);

    def xorHex(self,a,b):
        assert(len(a) == len(b));
        return hex(int(a,16) ^ int(b,16))[2:].zfill(32);

    def YourDidItCalculator(self,a):
        a = int(a,16);
        owo = self.YourDidIt.yourdidit(a);
        return hex(owo)[2:].zfill(32);

    def encryptHex(self,iv,pt):
        assert(len(bytes.fromhex(pt)) % self.BLOCK_SIZE == 0);
        ct = iv;
        prevXOR = iv;
        for i in range(0,len(pt),2 * self.BLOCK_SIZE):
            curBlock = pt[i:i + 2 * self.BLOCK_SIZE];
            e = self.encryptSingleBlock(self.xorHex(curBlock,prevXOR));
            ct += e;
            self.YourDidIt.infuseYourDidItPower(int(e,16),i);
            prevXOR = self.YourDidItCalculator(curBlock);
        return ct;

    def decryptHex(self,iv,ct):
        assert(len(bytes.fromhex(ct)) % self.BLOCK_SIZE == 0);
        prevXOR = iv;
        pt = "";
        for i in range(0,len(ct),2 * self.BLOCK_SIZE):
            curBlock = ct[i:i + 2 * self.BLOCK_SIZE];
            d = self.decryptSingleBlock(curBlock);
            p = self.xorHex(d,prevXOR);
            pt += p;
            self.YourDidIt.infuseYourDidItPower(int(curBlock,16),i);
            prevXOR = self.YourDidItCalculator(p);
        return pt;

    def pad(self,msg):
        l = (len(msg) % (2 * self.BLOCK_SIZE)) // 2;
        if(l == 0):
            msg = hex(self.BLOCK_SIZE)[2:] * self.BLOCK_SIZE + msg;
        else:
            msg = hex(self.BLOCK_SIZE - l)[2:].zfill(2) * (self.BLOCK_SIZE - l) + msg;
        return msg;


    def check_padding(self,msg):
        c = int(msg[:2],16);
        for i in range(c):
            if(int(msg[i * 2:i * 2 + 2],16) != c):
                return False;
        return msg[2 * c:];


    def check_MAC(self,msg):
        h = hashlib.sha1()
        mac = binascii.unhexlify(msg[-40:]);
        lastBlock = binascii.unhexlify(msg[-40 - 2 * 20 - 8:-40 - 8]);
        h.update(lastBlock);
        if(h.digest() == mac):
            return msg[:-40];
        else:
            return False;

    def encrypt(self,pt):
        iv = ''.join(random.choice("0123456789abcdef") for _ in range(32));
        h = hashlib.sha1()
        h.update(pt[-20:].encode("utf-8"));

        msg = self.pad(pt.encode("utf-8").hex() + hex(len(pt))[2:].zfill(8) + h.digest().hex());
        return self.encryptHex(iv,msg);

    def decrypt(self,ct):
        if(len(ct) % (2 * self.BLOCK_SIZE) != 0):
            print("Your did not do it D:");
            return;
        iv = ct[:32];
        c = ct[32:];
        msg = self.decryptHex(iv,c);
        msg = self.check_padding(msg);
        if not msg:
            print("Your did not do it D:");
            return;
        msg = self.check_MAC(msg);
        if msg:
            if len(msg[:-8]) == 2 * int(msg[-8:],16):
                print("YOUR DID IT!");
            else:
                print("Your did not do it D:");
        else:
            print("Your did not do it D:");
        return;

cipher = YourDidItAESCipher()

Welcome = "UwU the Your Did It Star wants to see if Your can did this challenge. I've heard that even the yourdidit star's cipher is different because of how yourdidit it is! Can you break it?"
print(Welcome);
options = """Select an option:
Encrypt a message so that yourdidit star can understand (E)
See if a message can be understood by the yourdidit star to check if your did it or not (V)
""";
while True:
    e_or_v = input(options);
    if("e" in e_or_v.lower()):
        yourdidit = input("Please enter your pre-yourdidit message: ");
        message = """There is something to be said about the your did it star. That somehow, despite its childishly cartoonish aesthetics (or perhaps more likely, because of), the people LOVE it. Such is the appeal of modern art, the decomposition and unraveling of conventions, mocking it through ironic depicitons, thus engendering sincerity. Sincerity? How could irony be a source of sincerity, you may ask. We as a society are so used to the insincere messages at the end of some grand services. The "thank you for choosing us" after the Airline cancelled your plane and rebooked you for one 30 hours after, and the "Great job!" on standard exams after you clearly bombed it. It is as if they don't acutally care about the message. They are but blindly following the nicities of yesterday's, churning out phrases one after the other. Thus, the Your Did It star stands as a beacon of sincerity and irony. The organizers know that most contestants probably didn't do as well as they hoped -- they didn't solve a problem despite their best efforts, they couldn't implement a solution before the time ran out, or they simply did worse than they wanted to. After all, there are only so many winners. Most don't stand out. So the Your Did It Star tells them: "It's ok! I know you probably didn't do so well, just like how I am not well-drawn. But it doesn't matter, because you had fun solving the problems, and ultimately this is just a silly contest. So regardless of what happened, your did it, even if your did it not so well." But you may argue that {0}. But I disagree!!! Because YOUR DID NOT DO IT!!!!!! Anywho, thanks for coming to my Ted-Talk. Here's the flag: {1}""".format(yourdidit,flag);
        print("Yourdidit-fied message: {}".format(cipher.encrypt(message)));
    elif("v" in e_or_v.lower()):
        cryptic = input("Please input a yourdidit message for verification: ")
        cipher.decrypt(cryptic);
```   
</details>
{::options parse_block_html="false" /}

## High-level challenge description

The challenge setup is somewhat verbose[^verbose] at 156 lines of code, but is not overly complicated. You are basically allowed to encrypt or verify any number of messages.

[^verbose]: I get to say this because my challenges tend to have very few lines. Do check out my [one-liner crypto challenge](/2023/onelinecrypto/)!

**Encrypting** roughly consists of:
1. Wrapping your text around some known random-looking text. The actual text can be seen in the source above and looks like `"There is ...<snip>... argue that {0}. But I ...<snip>... the flag: {1} ".format(input(), flag)`. It's over 1kb long, so for illustrative purposes we will replace it with the shorter `"[KNOWN_PREFIX]{0}[KNOWN_SUFFIX]{1}"`.
2. Append the length of the message (32-bit big-endian) as well as the SHA1 hash of the last 20 bytes of the message.
3. Finally, pad the message PKCS5-style to a multiple of 16 bytes, but prepend the padding at the start instead of the back.

At this point, an input of `"message"` would turn into something like this:
![](/assets/images/yourdidit-bd0af0b0-079c-455f-b25f-3ac099fa5bd3.png)
where we can see the padding (orange), last 20 bytes of the message (yellow) hashed into a 20-byte SHA1 (blue), and the length of the message (green).

4. Finally, this entire message is encrypted via AES using the YDI mode of operation and a random IV. This mode is, of course, entirely made up for this challenge, but it resembles [PCBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)) so we will try to adapt their diagram:

*[YDI]: Your Did It!

![](/assets/images/yourdidit-af11e9b1-99b1-4df2-845e-9ac15be0eda9.png)

The ciphertext printed to us will have the IV prepended at the start.

5. So what is this `YourDidIt` star function? Roughly speaking, it constructs an PRNG with the seed equal to some multiple (which is a multiple of 16, equal to the position of the block) of the ciphertext, ANDs the plaintext with the OR of five consecutive PRNG outputs, then returns the XOR of this with the next PRNG output.

More precisely, let's assume we have some `PRNG` class that takes in a seed and outputs uniformly distributed 128-bit values. The exact internals of the PRNG can be seen in the source, but I don't think it's breakable so I've left it as a black box for this discussion. Then we can define the `YourDidIt` function as follows:

```python
def YourDidIt(step, ciphertext, plaintext): # step = 0, 16, 32, ...
    r = PRNG(long_to_bytes(ciphertext) * step) 
    mask = r.next()|r.next()|r.next()|r.next()|r.next()
    star = r.next()
    return (plaintext & mask) ^ star
```

The key takeaway here is that each of the 128 bits of the `mask` has a 31/32 chance of being set, so on average we expect 124 set bits and 4 unset bits. Most importantly, the `mask` is a function of the ciphertext (and step), and not the plaintext, and we will exploit this fact in the next section.

**Verifying** is basically the reverse process, and consists of:

1. Letting the IV be the first 16 bytes of the input, and the rest of it be the ciphertext.

2. Reversing the encryption process above, into this decryption diagram:

![](/assets/images/yourdidit-e38dbfc3-498a-441c-b44d-a4521ea0d485.png)

3. Checking that at all of the following hold:
    - The front padding is valid (take `n = plaintext[0]` and checking that the first `n` bytes are all equal to `n`).
    - The length of the message is correct.
    - The hash at the end is in fact the SHA1 of the last 20 bytes of the message.

If all three are correct then print `"YOUR DID IT!"` otherwise print `"Your did not do it D:"`. In particular, we get no information about which check failed, and no information about the plaintext otherwise.

However, it also does mean that as long as the first block and last three blocks are valid, then anything in between is allowed to be any rubbish.

## The exploit itself

For the most part, I assumed this was a padding oracle challenge, i.e. place the encrypted flag at the start and change the first byte until it verifies (so it's equal to `01`, then the second byte until it verifies as `02 02` etc.). The problem is that once you change this first block, the error propagates to the end and you end up with invalid final three blocks so it doesn't verify there. And we don't have a way to distinguish whether verification is failing because of the first block or because of the last blocks.

It turns out the padding oracle is in fact the intended solution, but I did not figure out how to do this and left this approach. I will discuss the intended later in the write-up.

Anyhow, let's do something straightforward first, like learn the length of the flag. It's quite trivial, so I've made this section collapsible.

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Warmup: Learn that the length of the flag is 56</summary>

Let's just encrypt all messages of length 0 to 15, and see how long the encrypted message is:
    
```python
from pwn import *
sh = remote('litctf.org', 31789)
for _ in range(16):
    sh.sendlines([b'E', bytes(_)])
    sh.readuntil(b'fied message: ')
    print(_, len(bytes.fromhex(sh.readline().decode())))
```
    
which produces the result

```
0 1744
1 1744
2 1744
3 1744
4 1760
5 1760
6 1760
7 1760
8 1760
9 1760
10 1760
11 1760
12 1760
13 1760
14 1760
15 1760
```

There is a jump from three to four, that's when the padding goes from 1 to 16, which indicates that the length of the message for an empty input is 1740. We can remove various other things:
- The IV at the start is 16 bytes
- The length of `messagetemplate.format('','')` is 1644 bytes
- The length plus hash at the end is 24 bytes

Consequently, the length of the flag is $56 = 1740 - 16 - 1644 - 24$.
</details>
{::options parse_block_html="false" /}

Otherwise, the rough high-level idea is we construction an encryption oracle which we can use to complete any block, as long as we know the last prevXOR. We don't know this for the encrypted flag, but we can get around it by placing two copies of the block. Finally, this gives us a decryption oracle where we can learn any one bit at a time.

### Construct an encryption oracle

First thing we notice is that we can ECB-encrypt arbitrary blocks. This is not immediately obvious, because:
1. The input we provide must be ASCII. Well technically it can be UTF-8, but that only makes things more confusing so let's just assume ASCII and make it 1-to-1 with bytes. So anything from `\x00` to `\x7F` (other than `\n`) is fair game for our input.
2. The thing that gets encrypted is not our input directly, but our input XORed with some prevXOR. We don't have full control over this at the encryption stage since it starts with a random IV.

However! If we look carefully at the encryption diagram again, the first YourDidIt star takes in a seed of 0 (any ciphertext times 0 equals 0). Since the plaintext coming into it is constant, we always know what the prevXOR is here, and thus all subsequent prevXORs.

In other words, suppose we want to encrypt some arbitrary block called `plaintext`. First we encrypt some very long message (say 5MB long), so that we get lots of prevXORs. If any one of these satisfies the property that `prevXOR xor plaintext` is made up entirely of bytes in [0..127]\{10}, then we can truncate our original long message at this point and append `prevXOR xor plaintext` to it. This would cause `plaintext` to be encrypted into the corresponding `ciphertext` and we are done.

Does such a prevXOR always exist though? For any given `plaintext`, the probability that a given prevXOR could make it work is $\left(\frac{127}{256}\right)^{16} \approx \frac{1}{74298}$. Roughly speaking, if our original message was $74298 \times 16$ or roughly 1.2MB long, we would expect _on average_ one matching prevXOR. Making it 5MB long just gives a 4x safety margin so you're more likely to find a matching prevXOR.

At the end of the day, it's still possible that there are some `plaintext`s without a corresponding `prevXOR`. For our use case we can just ignore these, but if you want a higher success rate you can just keep encrypt an even longer message.

Anyway, that concludes the encryption oracle. We have one query at the start to prepare all the prevXORs, and then each time we want to encrypt we find a single corresponding prevXOR and construct a query with the plaintext injected at that point.

### Creating valid final-three-blocks

This seems kinda trivial now that we have arbitrary encryption. The only requirement here is that we need to know the prevXOR coming into this antepenultimate[^ante] block.

[^ante]: This is a fun word that just means third-last.

We can construct literally any final-three-blocks here, but I'm very boring so I place 24 bytes of `00`s, 4 bytes of length, and then 20 bytes of SHA1.

![](/assets/images/yourdidit-9121f3fe-5e1a-4c35-bfca-7f3e62e9d728.png)

Technically we only need to construct the last two blocks, since we can place anything in the antepenultimate block (as long as we know its corresponding plaintext).

### Turning this into a decryption oracle

So the idea is starting to fall into place. If we have a block `encrypted_flag` that we want to decrypt, we could use the padding oracle method at the start, but also construct valid final-three-blocks.

But wait, this requires knowledge of the prevXOR coming into it. However, we do not know this because it depends on `decrypted_flag` which we do not know.

Fortunately, we can get around this by placing two copies of `encrypted_flag` next to each other, as in the following image:

![](/assets/images/yourdidit-3ed01c31-59e2-48a7-9363-ceaf522a37d0.png)

Recall that the YourDidIt function is basically:
```python
YDI(s,ct,pt) = (pt & mask(ct*s)) ^ star(ct*s)
```

What happens here is that we do not know the first plaintext (`pt = d^iv`), but we do know the mask and the star. If it so happens that `(pt & mask) == pt`, then the approximation in the diagram is an equality, and we know the plaintext of the next block. This is independent of the unknown `d`, so we can proceed to forge the rest of the blocks since we know the outgoing prevXOR.

In other words, the key point here is:

**If `(pt & mask) == pt`, then the whole message will verify correctly.**

Or to take the contrapositive:

**If the message does not verify, then `(pt & mask) != pt`, or equivalently `(pt & ~mask) != 0`.**

This then tells us something about the plaintext `pt`! Namely, that one of the unset bits in `mask` corresponds to a set bit in `pt`. In particular, if `mask` has exactly one unset bit, then we know that the corresponding bit must be set in `pt`.

But we have some control over `mask`, as it's a function of the ciphertext (which we want to decrypt) as well as the step. By modifying the `step`, we can basically randomise this `mask` until we get one that we want. In particular, a mask that has has exactly one unset bit occurring in a given position is approximately $\frac{1}{32}\left(\frac{31}{32}\right)^{127} \approx \frac{1}{1804}$, so we can decrypt a particular bit by trialling approximately 1800 steps to find an appropriate mask.

Of course, this can only tell us if the plaintext `pt := d^prevXOR` has a set bit. (Remember the contrapositive? If the message verifies, we have no information about the bit.) So if that happens, then we just keep retrying it at different `step`s with the same mask, and eventually we will learn the bit.

### Constructing the single-bit decryption oracle

Alright, we have all the ingredients we need! Suppose we have a ciphertext `c` and we want to determine the bit value of `decrypt_ECB(c)` at position `n` (between 0 and 127 inclusive).

As outlined above, we roughly do the following:
1. Use a pre-existing first block with known padding
2. Calculate the step `s` where we get `mask(c*s)` to have its only unset bit in position `n`
3. Add many filler blocks between steps 1 and `s`. We can do this perfectly as we know all ciphertexts and plaintexts in between
4. Place two copies of the block `c`. At this point, we no longer what the plaintexts are.
5. Assume we know the prevXOR coming out of this anyway (by assuming `(pt & mask(c*s)) == pt`, as per the previous section). Then construct valid final-three-blocks.
6. Send this message for verification.
7. If it verifies, then we have learnt nothing, so go back to step 2 with a different value of `s`.
8. Otherwise, it does not verify, so we know the plaintext bit is set! Thus the ECB-decrypted bit is just the opposite of the `prevXOR` coming into it.

And that's the hard part done!

### Getting the flag

The rest of it is pretty straightforward, so there's nothing to describe really.

If we can decrypt any given bit, then we can decrypt an entire block. So just decrypt the encrypted flag one block at a time (xoring with any `prevXOR` as necessary).

## Solve script

Ok, I lied and don't actually have a single (proper) solve script that encompasses the above. This is largely because:
1. My solve process constantly evolved throughout the process. For example, earlier on I allowed the masks to have arbitrarily many unset bits (which is equivalent to an OR), but this turned out to give little, if any, information.
2. For the same reason as above, I didn't decrypt bits left-to-right (or right-to-left), instead getting tedious relations between various bits.
3. I ran multiple versions of different scripts that tried subtly different things, because I hadn't mathematically worked out why certain processes worked, or whether they were optimal.

The first block, for example, took the longest at over 2 hours, even though you already knew half the block.

Instead, I realised that these relations (e.g. `bit 0 = 1 or bit 4 = 0`) could be narrowed down by crib dragging[^crib], so I'll try to record what I do remember from this process. In theory the script should solve the whole flag eventually with no manual intervention, but I estimate that crib dragging halved the total time it took.

[^crib]: This is just a fancy cryptographical way of saying "guessing". Roughly speaking, you guess one part of the flag to see if illuminates other parts of the flag, so to speak.

Maybe at some point in the future I'll consolidate my scripts together into something of a solve script, but at this point it's quite unusable and undecipherable.

### The first block

The first block is `LITCTF{D1d_y0uR_`.

Roughly speaking, the relations I had showed that underscores were more likely to appear in the 11th and 16th bytes, so once I assumed these were underscores, there were very few phrases that looked like words. The most promising ones were those that began with some l33tification of "did your", and there were maybe 24 possibilities for these.

Fortunately, we have an encryption oracle which makes it easy to test if an entire block of the flag is correct. In this case, one of them was, so on to the next block!

### The second block

The second block is `d0_14_Yours31f_0`.

I think I saw "your" quite early on, and though it was of the form `xxxxx_your_xxxxx` but couldn't quite figure out how to make it grammatical. At some point decided to place an extra underscore, thinking it was "did your XX or your XX", when I realised the "Your Did It" isn't grammatical in the first place.

However! The relations I had did not allow "do it", mainly because I had `t` as one of `t, T, 7` rather than a `4`[^four]. But the `do_i?_` format allowed "yourself" to come out very nicely, so I decided it must be that. I assumed it was a `4`, but allowed other characters as well. And there was a free character at the end, but I think there weren't too many choices there.

If I recall correctly, I was left with some 60 options here, and again the oracle showed that one of them was in fact correct. More time saved!

[^four]: What kind of monster uses `4` for a `T`? It's an `A` and nothing else.

### The third block

The third block is `r_d1d_W3_d0_i4_T`.

At this point I had improved my script to only look for masks with exactly one or two unset bits. This made the bit determination a lot faster.

Anyway, because of the `0` at the beginning of the previous block, I think I immediately guessed that it begins with "or did", which turned out to fix a lot of the underscores, which made the rest of the words two letters long.

One of the options that jumped out at me was "TI 84", as in the calculator. So something along the lines of "did your do it yourself or did TI 84 do it for you", which seemed reasonable to me at the time, other than it didn't really work.

But! If I pushed it back to "did_TI_do_it", it worked quite nicely, and in fact makes the "it" appear as a "i4" which was surely correct. I pushed some options to the oracle, and none of it worked, so I just removed the TI and looked through the options again.

From the shortlist I spotted "we", which I guess is more obviously correct in hindsight. Again, there were maybe 40 l33tifications of the phrase with an unknown ending letter, and one turned out to be right.

### The final block

The final block is `0gE4h3r}`.

Remember how we already determined that the flag was 56 bytes long? This means the remainder was seven characters plus a closing brace. Given the rest of the phrase I was 80% sure it was going to be some l33tification of "together".

Because I was triggered by the `4` earlier, I tried to overpick the possible characters, resulting in a regex of `[oO0][gG69][eE3][tT47][hH4][eE3][rR2]` for some 4000 possibilities. And unfortunately the good ol' check-the-block oracle is not good enough here because we don't have a full block.

So I just ran the same script, but this time targeted at positions which would help distinguish the possibilities. As a result, this block fell fairly quickly -- there were only 24 possibilities left after half an hour and I just submitted all of them to the website, and one of them was correct!

The flag is `LITCTF{D1d_y0uR_d0_14_Yours31f_0r_d1d_W3_d0_i4_T0gE4h3r}`.

## Intended solution

While it was certainly a happy ending for me, my above solution for the challenge turned out to be completely unintended. The intended solution was meant to be orders of magnitude easier to implement. It just relies on noticing a single trick.

So what is this trick?

In short, it's this: If you encrypt a long enough message, then flip some bits near the start (though maybe not the IV or the first block, since that might ruin the padding), then this altered message will still verify.

Wha.... how!?? Doesn't that ruin the final three blocks?

Nope. And it's actually somewhat obvious from an error propagation point of view. Since the YourDidIt seed is a function of the ciphertext and step (which haven't changed), the masks and stars after a certain point also remain unchanged. In which case we could think of an error as coming from one `prevXOR`, which causes the plaintext to change, and this propagates into the next `prevXOR`.

There are two points of note here:
1. The error is independent between bit positions. An error in the bit position 42 say, will not propagate to any other bit position.
2. This error only continues to propagate until it gets masked out by some YourDidIt mask. After that point it becomes indistinguishable from the original stream.

So how many blocks do we need to ensure that the error has vanished by the end? As always, we can't guarantee anything. But after $n$ blocks, the probability that the error has vanished is roughly $\left(1 - \left(\frac{31}{32}\right)^n\right)^{128}$. At $n=200$ blocks, this is roughly an 80% chance, which is probably good enough. Or at $n=300$ blocks, 99%.

Anyway, once you know this trick you can just do a padding oracle on the first block, and it's all pretty straightforward from there.

{::options parse_block_html="true" /}
<details>
<summary markdown="span">Solve script for intended path</summary>

```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from Crypto.Cipher import AES
from pwn import *
from tqdm import trange

class YourDidItRNG:
    def __init__(self,size):
        self.mask = (1 << size) - 1;
        self.mod = 79563462179368165893806602174110452857247538703309854535186209058002907146727;
        self.seed = 0;

    def infuseYourDidItPower(self,power,step):
        self.seed = (step * power) % self.mod;

    def next(self):
        self.seed = ((self.seed * 573462395956462432646177 + 7453298385394557473) % self.mod); # try converting these to text ;)
        return self.seed & self.mask;

    def yourdidit(self,goodjob):
        for i in range(5 * 5):
            self.next();
        YourSoDidIt = self.next() | self.next() | self.next() | self.next() | self.next();
        YourSoDidIt = ((YourSoDidIt & goodjob) ^ self.next()) & self.mask;
        return YourSoDidIt

def ydi(step, ct, pt):
    y = YourDidItRNG(128)
    y.infuseYourDidItPower(btl(ct), step)
    return y.yourdidit(btl(pt)).to_bytes(16, 'big')
    
def star(step, ct):
    y = YourDidItRNG(128)
    y.infuseYourDidItPower(btl(ct), step)
    for i in range(30):
        y.next()
    return y.next().to_bytes(16, 'big')

sh = remote('litctf.org', 31789)

def getmsg(inp):
    sh.sendlines([b'E', inp])
    sh.readuntil(b'fied message: ')
    return bytearray.fromhex(sh.readline().decode())
    
orig = getmsg(b'')
lastknown, n = b"ere's the flag: ", -80

while b'}' not in lastknown:
    flag = orig[n:n+16]

    prevXOR = ydi((len(orig)+n-32)*2, orig[n-16:n],  lastknown)

    known = []
    for j in range(1,17):
        enc = getmsg(bytes(5012 - j))
        enc[16:32] = flag
        
        for i in range(len(known)):
            enc[i] = known[i] ^ j
        for i in trange(256):
            enc[j-1] = i
            sh.sendlines([b'V', enc.hex().encode()])
            if b'YOUR DID IT!' in sh.readline_contains(b'verification:'):
                known.append(i ^ j)
                break
        else:
            assert False, 'BROKEN'

    lastknown = xor(known, prevXOR)
    print(lastknown)
    n += 16
```
    
This printed the following on my system, which probably took about an hour:
```
[+] Opening connection to litctf.org on port 31789: Done
 99%|████████████████████████████████████████████████████████████████████████████████▎| 254/256 [01:46<00:00,  2.38it/s]
 77%|██████████████████████████████████████████████████████████████▎                  | 197/256 [01:22<00:24,  2.39it/s]
 26%|█████████████████████▏                                                            | 66/256 [00:27<01:20,  2.36it/s]
 93%|███████████████████████████████████████████████████████████████████████████▎     | 238/256 [01:39<00:07,  2.39it/s]
 14%|███████████▊                                                                      | 37/256 [00:15<01:33,  2.34it/s]
 41%|████████████████████████████████▉                                                | 104/256 [00:43<01:03,  2.38it/s]
 84%|███████████████████████████████████████████████████████████████████▋             | 214/256 [01:29<00:17,  2.39it/s]
 67%|██████████████████████████████████████████████████████▍                          | 172/256 [01:11<00:34,  2.41it/s]
 30%|████████████████████████▉                                                         | 78/256 [00:32<01:14,  2.38it/s]
 40%|████████████████████████████████▌                                                | 103/256 [00:43<01:04,  2.38it/s]
 14%|███████████▏                                                                      | 35/256 [00:14<01:34,  2.35it/s]
 73%|██████████████████████████████████████████████████████████▊                      | 186/256 [01:17<00:29,  2.40it/s]
 14%|███████████▏                                                                      | 35/256 [00:14<01:34,  2.35it/s]
 90%|█████████████████████████████████████████████████████████████████████████        | 231/256 [01:36<00:10,  2.40it/s]
 35%|████████████████████████████▊                                                     | 90/256 [00:37<01:10,  2.37it/s]
 95%|████████████████████████████████████████████████████████████████████████████▉    | 243/256 [01:41<00:05,  2.38it/s]
b'LITCTF{D1d_y0uR_'
 97%|██████████████████████████████████████████████████████████████████████████████▊  | 249/256 [01:44<00:02,  2.39it/s]
 28%|███████████████████████                                                           | 72/256 [00:30<01:17,  2.37it/s]
 82%|██████████████████████████████████████████████████████████████████▍              | 210/256 [01:28<00:19,  2.37it/s]
 67%|██████████████████████████████████████████████████████                           | 171/256 [01:11<00:35,  2.39it/s]
 93%|███████████████████████████████████████████████████████████████████████████▎     | 238/256 [01:39<00:07,  2.39it/s]
 30%|████████████████████████▉                                                         | 78/256 [00:32<01:15,  2.36it/s]
 16%|█████████████▏                                                                    | 41/256 [00:17<01:31,  2.35it/s]
 20%|████████████████▎                                                                 | 51/256 [00:21<01:27,  2.35it/s]
 16%|████████████▊                                                                     | 40/256 [00:17<01:32,  2.34it/s]
 22%|██████████████████▎                                                               | 57/256 [00:24<01:25,  2.34it/s]
 33%|██████████████████████████▉                                                       | 84/256 [00:35<01:12,  2.37it/s]
 98%|███████████████████████████████████████████████████████████████████████████████▍ | 251/256 [01:45<00:02,  2.38it/s]
 77%|██████████████████████████████████████████████████████████████▎                  | 197/256 [01:22<00:24,  2.39it/s]
  1%|▉                                                                                  | 3/256 [00:01<02:21,  1.79it/s]
  0%|                                                                                           | 0/256 [00:00<?, ?it/s]
 29%|███████████████████████▍                                                          | 73/256 [00:30<01:17,  2.36it/s]
b'd0_14_Yours31f_0'
 36%|█████████████████████████████▍                                                    | 92/256 [00:38<01:09,  2.37it/s]
 80%|█████████████████████████████████████████████████████████████████▏               | 206/256 [01:26<00:21,  2.38it/s]
 95%|████████████████████████████████████████████████████████████████████████████▉    | 243/256 [01:41<00:05,  2.39it/s]
 51%|█████████████████████████████████████████▏                                       | 130/256 [01:01<00:59,  2.13it/s]
 96%|██████████████████████████████████████████████████████████████████████████████▏  | 247/256 [01:56<00:04,  2.12it/s]
 54%|███████████████████████████████████████████▉                                     | 139/256 [01:05<00:55,  2.11it/s]
 92%|██████████████████████████████████████████████████████████████████████████▎      | 235/256 [01:50<00:09,  2.12it/s]
 48%|██████████████████████████████████████▉                                          | 123/256 [00:58<01:02,  2.12it/s]
 35%|████████████████████████████▌                                                     | 89/256 [00:42<01:19,  2.09it/s]
 29%|████████████████████████                                                          | 75/256 [00:35<01:26,  2.10it/s]
 78%|██████████████████████████████████████████████████████████████▉                  | 199/256 [01:31<00:26,  2.18it/s]
 77%|██████████████████████████████████████████████████████████████▎                  | 197/256 [01:22<00:24,  2.39it/s]
 69%|████████████████████████████████████████████████████████                         | 177/256 [01:13<00:32,  2.39it/s]
 89%|███████████████████████████████████████████████████████████████████████▊         | 227/256 [01:34<00:12,  2.39it/s]
 88%|███████████████████████████████████████████████████████████████████████▌         | 226/256 [01:34<00:12,  2.39it/s]
 36%|█████████████████████████████▏                                                    | 91/256 [00:38<01:09,  2.38it/s]
b'r_d1d_W3_d0_i4_T'
 48%|██████████████████████████████████████▉                                          | 123/256 [00:52<00:56,  2.36it/s]
 37%|██████████████████████████████▍                                                   | 95/256 [00:45<01:16,  2.09it/s]
 94%|███████████████████████████████████████████████████████████████████████████▉     | 240/256 [01:53<00:07,  2.12it/s]
 27%|██████████████████████▍                                                           | 70/256 [00:33<01:28,  2.10it/s]
 71%|█████████████████████████████████████████████████████████▉                       | 183/256 [01:26<00:34,  2.11it/s]
 91%|█████████████████████████████████████████████████████████████████████████▍       | 232/256 [01:49<00:11,  2.12it/s]
  4%|███▌                                                                              | 11/256 [00:05<02:05,  1.96it/s]
 13%|██████████▌                                                                       | 33/256 [00:16<01:48,  2.06it/s]
 34%|███████████████████████████▌                                                      | 86/256 [00:40<01:20,  2.10it/s]
 36%|█████████████████████████████▊                                                    | 93/256 [00:44<01:17,  2.10it/s]
 36%|█████████████████████████████▍                                                    | 92/256 [00:43<01:17,  2.10it/s]
 61%|█████████████████████████████████████████████████▎                               | 156/256 [01:13<00:47,  2.12it/s]
 16%|████████████▊                                                                     | 40/256 [00:19<01:43,  2.08it/s]
 65%|████████████████████████████████████████████████████▌                            | 166/256 [01:18<00:42,  2.11it/s]
 15%|████████████▍                                                                     | 39/256 [00:18<01:44,  2.08it/s]
 30%|████████████████████████▎                                                         | 76/256 [00:36<01:25,  2.10it/s]
b'0gE4h3r}\x00\x00\x06\xa4\xa0\xc6\xbd\x8d'
[*] Closed connection to litctf.org port 31789
```
</details>
{::options parse_block_html="false" /}