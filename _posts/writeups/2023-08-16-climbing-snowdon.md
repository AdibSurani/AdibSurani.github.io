---
title: "Climbing Snowdon"
categories:
  - writeup
tags:
  - LITCTF
  - crypto
---

Croeso i Gymru!

Well now, I'm Snowden, a bit of a cheeky Welsh hacker, I am.

<!--more-->

![that's me](https://upload.wikimedia.org/wikipedia/commons/6/60/Edward_Snowden-2.jpg)

Tinkering with them digital bits and bobs, I do. But let me share a bit of a tale, a playful one, mind you.

There's this towering beauty they call Mount Snowdon, y'see.

![snowdon](https://upload.wikimedia.org/wikipedia/commons/6/6c/Snowdon_massif.jpg)

Now, it's not exactly named after me, no no, but it tickles me fancy to think of it that way, it does. A bit of whimsy, aye?

Anywho, I was climbin' up Garn Boduan the other day, like, when I caught sight of this message, I did.

> Dfizgwiy y prwn a gcejaos tensgn argln yx gciygo socz dsidhso myza xhetdwc tqcctkl c dnozimu e byluheu oyjahtwl rhunednyxt
>
> Lwi wir aiyimul socz gqfb yxa
>
> Adsrwn ketevlkexhwl uysrc ys mbon pxil latfrannaw yqr qyjrunait

Seein' as I was up on a hill, it's only logical to reckon that it might just be encrypted with the Hill cipher, you know.

And would ya believe it, the first Google search result whisked me straight to a [Hill cipher decoder](https://www.dcode.fr/hill-cipher), it did.

I din't even know what the key was, but it doesn't matter 'cos this solver is so bloomin' good at what it does, see?

![](/assets/images/climbingsnowdon-d4e8a512-2220-415a-87e9-819120b4d290.png)


No true Welshman wouldn't recognise the first message as bein' Welsh, mind you. Here's the full output, it is.

> Dringais y bryn a gwelais berson arall yn gwisgo sach deithio gyda phatrwm tecstil o ddotiau a bylchau cyfartal rhyngddynt
> 
> Dwi wir eisiaur sach gefn yna
>
> Aderyn cenedlaethol cymru ym mhob prif lythrennau ywr cyfrinair

{::options parse_block_html="true" /}
<details>
<summary markdown="span">
Or here's a Google translation if your school never taught you Welsh, mind you.</summary>

> I climbed the hill and saw another person wearing a rucksack with a textile pattern of evenly spaced dots
>
> I really want that backpack
>
> The national bird of Wales in all capital letters is the password
</details>
{::options parse_block_html="false" /}

Anyway, I used the RED KITE to unzip the rucksack, only to find this peculiar lookin' pattern, you know.

![](/assets/images/climbingsnowdon-7bc1b4df-bcd6-4cd1-9e35-41fb6377f387.png)

Aye, I do realise the Fjällräven Kånken is Swedish, mind ye, but it's also immensely popular here in Wales, it is.

Now, I noticed there were some repeats in the pattern, so I noted it down as such, see?

![](/assets/images/climbingsnowdon-d8a7d228-c642-47b5-a7cd-6c2e7b8ae590.png)

This is clearly a cryptogram, it is. And would ya believe it, the first Google search result whisked me straight to a [cryptogram solver](https://quipqiup.com/), it did.

![](/assets/images/climbingsnowdon-197a31a5-5817-4bf7-ace6-afb7bfca342c.png)

And there it is, that was my first taste of the flag, see? The voice in my head also told me it was all lowercase, which was good, it was. But there were still a couple of questions, mind you:
1. Why was "CLIMBING" spelled wrong, then?
2. Are the dashes in the image actually dashes? Or underscores? Or even spaces?

No matter, we can try all six possible flags:
```
LITCTF{maybe-i-shall-try-climing-a-peak-after-this}
LITCTF{maybe_i_shall_try_climing_a_peak_after_this}
LITCTF{maybe i shall try climing a peak after this}
LITCTF{maybe-i-shall-try-climbing-a-peak-after-this}
LITCTF{maybe_i_shall_try_climbing_a_peak_after_this}
LITCTF{maybe i shall try climbing a peak after this}
```

And lo, all six flags stood wrong, a dramatic twist of fate, it was.

'Twas the hour to unseal the dreaded ticket, a moment of reckoning, it was.

![](/assets/images/climbingsnowdon-95a6a85d-7334-451f-9754-27fc4203204a.png)

And therein lies the crucial hint, see?

> An aristocrat solver will not get you the exact flag

The flag might contain numbers, or even other symbols, mind you!

The rule of l33t suggests these modifications: `i->1, e->3, a->4`.

And it turns out, that was the flag all along, in a twist of fate beyond reckonin', it was!

The flag is `L1TCTF{m4yb3_1_sh4ll_try_cl1m1ng_4_p34k_4ft3r_th1s}`.

And then there was blood... 🔪🩸