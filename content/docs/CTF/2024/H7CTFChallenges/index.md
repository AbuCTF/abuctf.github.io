---
title: "H7CTFChallenges"
description: "Migrated from Astro"
icon: "article"
date: "2024-10-06"
lastmod: "2024-10-06"
draft: false
toc: true
weight: 999
---

Hello CTFers. Here are the documentation for challenge solutions for `H7CTF` , I’ll try to be as detailed as possible like the Infra documentation.

```bash
Authors: Abu, PattuSai, MrGhost, MrRobot, SHL, Rohmat, Zeta, Raghu, Josh, Tourpran
```

We’re excited to bring you a wide range of challenges across various domains, even including Boot2Root and Hardware. Another thing to note is that, there’s even a THM room incoming. Let’s get right into it.

Here are the current list of challenges, which could be changed in the upcoming days.

```txt
OSINT [6]

Scratch CS50 Find-out
Interstellar Double Pulsar
DKPC Church
Trump Assasination
Repo ID + Fork
Perl Password

Forensics [6]

Fourier Transforms
OpenStego
Steg86
PCAP
Zero-width stego
Zoom

Miscellaneous [4]

Info H7Tex
ArUco Markers
Had Lunch?
Feedback

Crypto [8]

Fermat's RSA
Base X
Rand Function
Frequency Analysis
GPPDecrypt
GravityFallsColour
I Lost My Bottoms
The Real Crypto

Pwn [2]

Format Strings
Ret2Win

Web [5]

JWT Cookie
IDOR
NoPaste
LFI[2]

Reverse [6]

WASM Decompiler
JSFuck
Horcrux
PattuSai[3]

Hardware [1]

PCB Inspect [Gerber Files]

Boot2Root [3]

THMRoom
	Enumeration
	Exploitation
	Privilege Escalation
```

This is has gone through a lot of changes, at the end, we managed to cook up 41 challenges overall. 

## Forensics

As usual, we take the Forensics route at the start.

Now, I’m looking at a collective challenge to make, it started off with Byte-Array PNG, moved on to Binary Images and now into Vector Graphics LOL. I’m looking at this things to actually learn on the process of creating them. Now into `ZLibs`. P.S. well, all that didn’t go so well, aspiring to create good challenges next time.

### **Khabib**

"I don't fight for the money. I fight for my legacy. I fight for history. I fight for my people." - Khabib Nurmagomedov

True to his words, the Eagle was one to watch out for, especially if you know where to look.

Author: **`Abu`**

Well, this challenge had the most solves in the CTF. So, when you `exiftool` the image, you would notice the dimensions for the image is huge. `20000 x 20000`

```bash
└─$ exiftool test.png
ExifTool Version Number         : 12.76
File Name                       : test.png
Directory                       : .
File Size                       : 1220 kB
File Modification Date/Time     : 2024:09:24 15:17:04+05:30
File Access Date/Time           : 2024:09:26 10:13:17+05:30
File Inode Change Date/Time     : 2024:09:24 15:17:04+05:30
File Permissions                : -rwxrwxrwx
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 20000
Image Height                    : 20000
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 20000x20000
Megapixels                      : 400.0
```

{{< figure src="1.png" alt="1" >}}

Flag: `H7CTF{PNG_z00mz_4r3_1mp0ss1ble_t0_n0t1ce}`

### Captain Cool

"It is better to keep your mouth closed and let people think you are a fool than to open it and remove all doubt." - Mark Twain

All that is good, but Thala spoke the golden words `d-e-f-i-n-i-t-e-l-y-n-o-t` .

Author: **`Abu`**

Given: `white.png`

Since the given image is a PNG [Portable Network Graphics] image, that itself reduces the scope of search by quite a margin. After going about trying OG tools like `zsteg` and others, you notice there is a string that Thala spoke the golden words, `d-e-f-i-n-i-t-e-l-y-n-o-t` . This definitely looks like a password,  now looking at some tools that can input PNGs and a password, we stumble upon `OpenStego`.

{{< figure src="2.png" alt="2" >}}

Open Stego with the password `d-e-f-i-n-i-t-e-l-y-n-o-t`, without the hyphens obviously, would give you a binary file.

Convert it to hex and then to ASCII, which gives you the flag.

flag: `H7CTF{7h1s_h4s_t0_b3_0n3_of_7h3_L4rg3s7_b1n4ry_im4g3s}`

### Blimey

"I don't pretend to be captain weird. I just do what I do." - Johnny Depp

Author: **`Abu`**

Given: `stego`

We’re given an executable in a Forensics challenge, pretty strange. 

```bash
└─$ file stego
stego: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=B9OUo6iP1s_hegoQnXM_/AoCYZrqNvR-EFLPnGGC1/0eqiKqmNKqAlwdnrTr2q/k8a5abbJQUx7DB3DynPL, with debug_info, not stripped
```

Other normal stuff, like strings, binwalk and when you run it. It seems it’s a `jsteg` tool. Well, that is another rabbit hole. `ELF 64-bit LSB executable, x86-64`. It’s a x86 file, so looking at tools related to x86 forensics.

Let’s move on to this, interesting tool which hides messages in x86 programs using semantic duals.

[Steg86](https://github.com/woodruffw/steg86)

```bash
cargo install steg86
```

`Cargo` is Rust's package manager.

```bash
steg86 embed random stego <<< "H7CTF{eXecu74bl3s_1n_s73g0_1s_qU1te_uh34rd_0ff}"
```

Now, the executable is ready for production.

```bash
└─$ steg86 extract stego
H7CTF{eXecu74bl3s_1n_s73g0_1s_qU1te_uh34rd_0ff}
```

Flag: `H7CTF{eXecu74bl3s_1n_s73g0_1s_qU1te_uh34rd_0ff}`

### **Evolve**

“Civilization is the subordination of the individual to the welfare of the community.” - Charles Fourier

Author: **`Abu`**

Given: `flag.png`

Given in the description is name of the person involves in this technique. Maybe I was wrong to select quotes as descriptions as I thought it would be better than some long-random-GPT generated messages. Will keep it in mind while doing it next time.

Well, this is another steganographic technique. Fast Fourier Transform (FFT) is a mathematical technique that transforms data between time (or spatial) domain and frequency domain. In the context of steganography, hiding data in the frequency domain involves manipulating the frequency components of an image or audio signal rather than directly altering pixel or sample values.

[BIG | Image Processing Online Demonstration | Fast Fourier Transform](https://bigwww.epfl.ch/demo/ip/demos/FFT/)

{{< figure src="3.png" alt="3" >}}

You can of course, write a script to solve this, but also a tool mentioned above.

{{< figure src="4.png" alt="4" >}}

Flag: `H7CTF{f0ur1er_7r4nsf0rms_4r3_c00L}`

### Empty

"When one's expectations are reduced to zero, one really appreciates everything one does have." - Stephen Hawking

Author: **`Abu`**

Given: `zero.zip`

We see that the zip is encrypted, so we run `john` and `rockyou` against it.

```bash
└─$ zip2john zero.zip > hash
ver 1.0 zero.zip/zero/ is not encrypted, or stored with non-handled compression type
ver 1.0 zero.zip/zero/‎/ is not encrypted, or stored with non-handled compression type
ver 1.0 zero.zip/zero/‎/.git/ is not encrypted, or stored with non-handled compression type
ver 1.0 zero.zip/zero/‎/.git/branches/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 zero.zip/zero/‎/.git/COMMIT_EDITMSG PKZIP Encr: TS_chk, cmplen=145, decmplen=188, crc=6274FC0F ts=9DAD cs=9dad type=8
<>
ver 2.0 efh 5455 efh 7875 zero.zip/zero/‎/.secret PKZIP Encr: TS_chk, cmplen=43, decmplen=101, crc=6191A448 ts=5906 cs=5906 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

Using `zip2john` to convert the encrypted zip hash into a format that john understands.

```bash
└─$ john --wordlist=rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
canyoutellmesomeinformationaboutyourself (zero.zip)
1g 0:00:00:06 DONE (2024-10-06 18:39) 0.1522g/s 1417Kp/s 1417Kc/s 1417KC/s capbulaly..candra02
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we get the password for the zip file = `canyoutellmesomeinformationaboutyourself` 

```bash
└─$ unzip zero.zip
Archive:  zero.zip
[zero.zip] zero/‎/.git/COMMIT_EDITMSG password:
replace zero/‎/.git/COMMIT_EDITMSG? [y]es, [n]o, [A]ll, [N]one, [r]ename: A
  inflating: zero/‎/.git/COMMIT_EDITMSG
  inflating: zero/‎/.git/config
  inflating: zero/‎/.git/description
 extracting: zero/‎/.git/HEAD
  inflating: zero/‎/.git/hooks/applypatch-msg.sample
  inflating: zero/‎/.git/hooks/commit-msg.sample
  <>
  inflating: zero/‎/.git/hooks/sendemail-validate.sample
  inflating: zero/‎/.git/hooks/update.sample
  inflating: zero/‎/.git/index
  inflating: zero/‎/.git/info/exclude
  inflating: zero/‎/.git/logs/HEAD
  inflating: zero/‎/.git/logs/refs/heads/master
 extracting: zero/‎/.git/objects/00/c9c49d3f1fdd2cb4ed8eb660e505e6603e1aac
 <>
 extracting: zero/‎/.git/refs/heads/master
  inflating: zero/‎/.secret
```

Using the password to unzip the zip file, we find that it’s a git repository.

Going into the directories, we see an directory with a `unicode` character. Going deeper, we see a `.secret` file.

```bash
└─$ ls -la
total 0
drwxrwxrwx 1 abu abu 512 Oct  6 18:47 .
drwxrwxrwx 1 abu abu 512 Sep 19 11:24 ..
drwxrwxrwx 1 abu abu 512 Oct  6 18:42 .git
-rwxrwxrwx 1 abu abu 101 Sep 19 11:08 .secret
```

{{< figure src="5.png" alt="5" >}}

We can make out that there is `white-space stego` involved here. Opening it in VS Code, could give a better view.

Using `stegsnow` against the `.secret` file.

```bash
└─$ stegsnow -C .secret
somethingrandom
```

Results in something meaningless. So moving on. On to the interesting `.git` directory.

```bash
└─$ git log
commit 764edd247a217f2e30a2b815a73af81bf551deed (HEAD -> master)
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 19:45:25 2024 +0530

    Bene vale cleopatra, hoc admodum iter debuit populo saeculi XXI, et speciales, qui ab imo inceperunt, hi sunt qui realem claritatem in vita agunt, te omnes in altera vita vident. mox pax.

commit 7048348fd3168bc684308f971e3338403c755542
Author: Cleopatra <cleopatra@egypt.com>
Date:   Tue Sep 24 19:42:34 2024 +0530

    الآن، الوقت قد توقف عن العمل، والأمر متروك لنا لصنع التاريخ

commit 2b02eb0fe4e9f6a9ceb353c4fc024f1eb65f0655
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 19:40:42 2024 +0530

    Imo tempus est involvere hunc absolutum tempus superfluum, at quisquis hoc longe ire ad ea quae sperant accipiendi sunt, hi descendent historia est sicut populus saeculi XXI.

commit edaf890ff3d4db4a570daba1e25e979616faf444
Author: Cleopatra <cleopatra@egypt.com>
Date:   Tue Sep 24 19:38:05 2024 +0530

    الآن، ملك روما يتصرف بسبب شيء بسيط مثل هذا؟ لقد اقتربنا حقًا من نهاية القصة، حتى نتمكن من جعلها أطول فترة ممكنة وما زلنا غير قادرين على معرفة القصد من وراء القصة

commit f08f494a39613341995d44c9ead657cca6d8cd58
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 19:34:31 2024 +0530

    Quid‌‌‌‌‍‌‬‌? ‌‌‌‌‌﻿‍﻿‌‌‌‌‍‌‌﻿Cleopatra‌‌‌‌‍‍‍‌ ‌‌‌‌‍‌‍‬erat,‌‌‌‌‍﻿‬﻿‌‌‌‌‍﻿‬‬ ‌‌‌‌‌﻿‌﻿‌‌‌‌‍﻿‌‬‌‌‌‌‌﻿‌‌quae ‌‌‌‌‍‍﻿﻿prima ‌‌‌‌‍﻿‍﻿moveret‌‌‌‌‌﻿‌‍, nunc ‌‌‌‌‍‬‍‌audet‌‌‌‌‌﻿‍﻿ ‌‌‌‌‍‬‬‌‌‌‌‌‍‍﻿﻿digitos‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿‍‌‌‌‌‌‍‬‍‍ ‌‌‌‌‍‬‍﻿in‌‌‌‌‌﻿‌‌‌‌‌‌‍‍﻿﻿ me‌‌‌‌‍﻿‌‬ monstrare‌‌‌‌‌﻿‌‌‌‌‌‌‍‬‌﻿‌‌‌‌‍‬‬﻿, hoc‌‌‌‌‌‬‍‌‌‌‌‌‍﻿﻿‍ est sine stultitia

commit d8d68aaa41dc77e85f510223bb3d3dcfa9fad496
Author: Cleopatra <cleopatra@egypt.com>
Date:   Tue Sep 24 17:22:41 2024 +0530

    كان قيصر هو الذي كان يركض خلفي مثل الأحمق، تاركًا وراءه جيشه الروماني بأكمله في الحبال

commit 7024ddb279380fb1941c3ef560f4f80469c220bf
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 16:58:23 2024 +0530

    Nullo modo est quod cleopatra modo me ineptum retulerit!

commit cef1c9b72380c1bf1312cf418fb997a5e748d4af
Author: Cleopatra <cleopatra@egypt.com>
Date:   Tue Sep 24 16:57:07 2024 +0530

    لأن قيصر يتصرف كالأحمق

commit 44edb1a7d490c6ccbb893bba15512165265b3a94
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 16:55:05 2024 +0530

    cur cleopatra cogitare me agere cerritulus

commit 38a7d2129b5d2ba4d7c02ac395034ac5cd48f29d
Author: Cleopatra <cleopatra@egypt.com>
Date:   Tue Sep 24 15:45:49 2024 +0530

    ‌‌‌‌‍‌‬ما الأمر مع سيزار، فهو يتصرف بغرابة
```

We see this huge commit messages in the logs, people actually went ahead and translated what `Cleopatra` and `Caesar` were talking about LOL. But if you look closely in this particular commit message.

```bash
commit f08f494a39613341995d44c9ead657cca6d8cd58
Author: Caesar <caesar@rome.com>
Date:   Tue Sep 24 19:34:31 2024 +0530
```

{{< figure src="6.png" alt="6" >}}

It seems all messed up, you have to question this. Doing so, will lead you to discovering a concept called `Zero-Width Steganography` and that is pretty cool.

[Unicode Steganography with Zero-Width Characters](https://330k.github.io/misc_tools/unicode_steganography.html)

Using it to decode the text, we get the flag. 

{{< figure src="7.png" alt="7" >}}

Flag: `H7CTF{z3r0_w1d7h_steg0_r0ck$}`

<aside>
💡

There was actually an unintended flag in the git repository, using a `gitdumper` on it, revealed a gimp.xcf file, which contained a flag for an unreleased challenge. It never struck my mind to check the files in the .git repo. 

</aside>

Here’s a little refresher on how to extract files from a local directory. Of course there should be tools for this, but there is this way as well.

To extract the files from the latest commit (i.e., the `HEAD` of the current branch), you can simply use:

```bash
└─$ git checkout .
Updated 1 path from the index
```

```bash
└─$ for commit in $(git rev-list --all); do
    echo "Extracting files from commit $commit"
    git checkout $commit -- .
done
Extracting files from commit 764edd247a217f2e30a2b815a73af81bf551deed
Extracting files from commit 7048348fd3168bc684308f971e3338403c755542
Extracting files from commit 2b02eb0fe4e9f6a9ceb353c4fc024f1eb65f0655
Extracting files from commit edaf890ff3d4db4a570daba1e25e979616faf444
Extracting files from commit f08f494a39613341995d44c9ead657cca6d8cd58
Extracting files from commit d8d68aaa41dc77e85f510223bb3d3dcfa9fad496
Extracting files from commit 7024ddb279380fb1941c3ef560f4f80469c220bf
Extracting files from commit cef1c9b72380c1bf1312cf418fb997a5e748d4af
Extracting files from commit 44edb1a7d490c6ccbb893bba15512165265b3a94
Extracting files from commit 38a7d2129b5d2ba4d7c02ac395034ac5cd48f29d
```

Now, you can see all the files that were in and out of the directory.

```bash
└─$ ls
fdct.go  gimp.xcf  photo.png  scan.go  some.aac
```

{{< figure src="8.png" alt="p4" >}}

And this was totally unintentional. Sorry HAHA.

## Cryptography

### **Color Blind**

Picasso’s final mystery lies in his colors.

Author: **`Abu`**

Given: `picasso.png`

{{< figure src="9.png" alt="p4" >}}

Use the `Gravity Falls Color Code` to decipher the hidden message.

[Gravity Falls Color Code](https://www.dcode.fr/gravity-falls-colors?__r=1.07924bcb788451af402f9d7ea2026ade)

```bash

h7ctf{onlyalifelivedforothersisalifeworthwhile}
```

Flag: `H7CTF{onlyalifelivedforothersisalifeworthwhile}`

### Base X

Description: "To solve complex problems, start with a simple base and build from there." — Unknown

Author: `Abu`

Given: `wTWY+%u_M_\1c`,\_D8A{1<[_i_aa/0|S)q)D247Dc$|@SQ1}_qawe8twW`

Long story short, the ideology behind this challenge is to help the participants help understand how bases work in detail. Starting off from Base64, which is the most common, if you look at the characters in the Base cipher, you see a lot of characters that are outside the Base64 range, so we move on. If you inspect the characters in detail, you would notice this character `}` , which is numbered 125 in the ASCII table, and that would point towards the printable ASCII characters, which are a total of 95 characters, and trying to decode this base cipher with the `Base94` encryption will reveal the flag.

<aside>
💡

The notes below are a rough idea of when I was creating the challenge, a lot of this and that, but I’ll leave this here, just in-case someone finds it helpful.

</aside>

Here’s explanation on how bases work in general, the bases correspond to the numbers of characters in the character set, let’s say base 2, which is binary, has only 2 characters to represent. Whereas in the case of base64, the character set is 64,  [ `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` ] and so on with base94, which uses 94 characters, I choose this unique and rare base encryption because the participants can know more about bases and how those work at least to some extent and also when you observe the individual characters in a given cipher, and you notice a character is that being used outside of the current count of base operation that the user is attempting only then will they be able to move on to finding the exact base encryption in hand. I also think the description does provide a route that the solver can profit from starting off from the most common and moving on to bases with larger character sets.

Moving on the next stage of encryption, the flag which is typically in alphanumeric format, is converted to binary for ease of operations, and then grouped together in chunks depending on the base. In base64, the binary data is grouped into 6-bit chunks as to represent 64 unique characters, you would need $2^6 = 64$, or at least 6 bit to represent these. In the case of base94, which has 94 unique characters, you would need $2^7 = 128$, which would easily cover the 94 character list.
We first ensure that the binary string length is a multiple of 7 by adding padding bits (`0`s). In our case, this is the `010010000011011101000011010101000100011001111011011000100011010001110011011001010101001101011111011000110011010001101110010111110110001000110011010111110110110100110000011001000011000101100110001100010011001101100100010111110110001000110011011110010011000001101110011001000101111101110010001100110110001100110000011001110110111000110001011101000011000100110000011011100111110100`, binary data which is 378 character long, with the last 2 0’s padded to make the entire data a multiple of 7. Then we divided it to 54 chunks of data. Then take each chunk and convert it to decimal before assign the encoded decimal to it’s equivalent in the character list. 

<aside>
💡

The tool mentioned seems to do the job but there are variances in each of them. I should prepare a script that follows these generic steps to avoid any nuances.

</aside>

Another point to note is that the user has be aware that, even though the entire data is divided into 7-bit chunks but the binary is getting read as a traditional 8-bit binary will lead to an incorrect solution. Finally, make sure to map the numbers to the exact characters corresponding to base94 characters, are the printable characters start from 33 onwards, you might need to substract 33 from the decimal as it exceed the character value of 0-93. Oh wait,  I think I messed up my ideology. I guess we need to `start over again.` With no time, sadly, we have to shift to the tool to implement this, but updating the title to `Base X`. L in the chat for my scripting skills, really need to put some work on them.

Now, when we use a tool to decipher the Base94, we reveal the flag.

[Base94-RS](https://github.com/Antosser/base94-rs)

```bash
cargo install base94

base94cli encode flag.txt base

base94cli decode base flag.txt
```

Flag: `H7CTF{b4seS_c4n_b3_m0d1f13d_b3y0nd_r3c0gn1t10n}`

### **OG Fermat**

It is impossible for any number which is a power greater than the second to be written as a sum of two like powers. I have a truly marvelous demonstration of this proposition which this margin is too narrow to contain.

Author: **`Abu`**

Given: `chal`

```bash
n = 19941761574905742888287481436741891092124181365374951557784462831976463640107265018634834348445714890239773671635245721007690323617473110640838905137749040079027523456576873242576882348266023282328418714706775196352487380997352642934338999701240803315143633815388891936049690566875086476878846288179053430346474607507140036260924419560806005408849547824680623840905827643373832321736642361809029363098769822048159935628385558949380403530181068302284344450193809037352292218892697094260257903235373427839438588016417069626966199168116250816624950794879795025563625197229849548571880188149181610538268071041049047969843
e = 65537
c = 1988485752816603419429035490102559454780640153479719954958054370853221253149463242805549913884352375195700573804489468586048166293155196062139063129843463305054035591340171382191970297264224412110518921248838305263451454271891276948057908147173115246465013260604658154061664201662794103501624159673086264544744757112772145863773180603668686462400409710020777353930439223484072904284076703999739531521180376362124667231087662531121127471008963508634982558020180434738014455407480013270833949762016165945215121280663999417751212723592001289388652238561621848346407525794583039448395153917679000964636455519953229458XXXX
```

Here’s a typical RSA encryption with a twist, the last 4 digits of the ciphertext is redacted, the idea is to prevent the usage of tools like `dCode` or some RSA cracking software. Now, we write a script to solve this problem, essentially bruteforcing the last 4 digits in the cipher to reveal the plaintext.

```bash
from Crypto.Util.number import long_to_bytes
import math

n = 19941761574905742888287481436741891092124181365374951557784462831976463640107265018634834348445714890239773671635245721007690323617473110640838905137749040079027523456576873242576882348266023282328418714706775196352487380997352642934338999701240803315143633815388891936049690566875086476878846288179053430346474607507140036260924419560806005408849547824680623840905827643373832321736642361809029363098769822048159935628385558949380403530181068302284344450193809037352292218892697094260257903235373427839438588016417069626966199168116250816624950794879795025563625197229849548571880188149181610538268071041049047969843
e = 65537

RedactedC = 1988485752816603419429035490102559454780640153479719954958054370853221253149463242805549913884352375195700573804489468586048166293155196062139063129843463305054035591340171382191970297264224412110518921248838305263451454271891276948057908147173115246465013260604658154061664201662794103501624159673086264544744757112772145863773180603668686462400409710020777353930439223484072904284076703999739531521180376362124667231087662531121127471008963508634982558020180434738014455407480013270833949762016165945215121280663999417751212723592001289388652238561621848346407525794583039448395153917679000964636455519953229458

def fermat(n):
    a = math.isqrt(n)
    b2 = a * a - n
    while b2 < 0 or not math.isqrt(b2) ** 2 == b2:
        a += 1
        b2 = a * a - n
    b = math.isqrt(b2)
    p = a - b
    q = a + b
    return p, q

for i in range(10000):
    c = RedactedC * 10000 + i

    p, q = fermat(n)
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
        plaintext = pow(c, d, n)
        flag = long_to_bytes(plaintext)
        if flag.startswith(b'H7CTF{'):
            print(f"Flag found: {flag.decode()}")
            break
    except ValueError:
        continue
```

It’s not the most efficient code, but it takes about `6` minutes to execute.

Flag: `H7CTF{f3rm@t_r3@lly_l2f7_@!!_7h3se_unpr0v3d!}`

### Hertz

"Machines take me by suprise with great frequency" - Alan Turing

Author: **`Abu`**

Given: `doom` - `cipher`

```bash
└─$ cat doom
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)(b'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'))

└─$ cat cipher
⥾⋄⥽⥾≧⋄⥽ ≧⨂⊛ ⥮⊖♺⊝⥽ ⋑⦿⥽ ⥽⨂⊕⟆⟒≧ ⋉⊘ ⊕⨂⊝⥽⥮⋑⊕⟆≧⋑⊕⨂⟆ ⨂⥽⋓ ⊚⥫⨂✷⋑⊕⊖⨂⥮. ✵-⟒≧⋄⨅⥽⊛ ♢⊕⨂⊛⊕⨂⟆⥮ ⥮⊖⊖⨂ ⊕⨂ 7 ≧⨂⥮⋓⥽⋄⥮ ⋉⥽✷⨅⊖⨂. ⦿7✷⋑♢{✷⋄⊘⥾7!✷_⟒⊘$⋑3⋄1⥽⥮_4⋄⥽_⟒3@⨂7_70_⋉3_✷⋄4✷⨅3⊛!}
```

The doom file looks like an obfuscated code. Go ahead an deobfuscate it.

```bash
txt = "≧⋉✷⊛⥽♢⟆⦿⊕⊚⨅♺⟒⨂⊖⥾≊⋄⥮⋑⥫⊝⋓✵⊘⧫"
print(len(txt))
#aHR0cHM6Ly9yYi5neS9nNXY4Mmc=
```

Running the file.

```bash
└─$ python3 doom.py
26
```

Gives us `26`,which corresponds to the characters of the alphabets. Now the concept behind this is to reverse map each character to it’s corresponding alphabet is ASCII. Also the cipher file, like the name contains the cipher LOL.

```bash
alphabet = "abcdefghijklmnopqrstuvwxyz"
syms_26 = ['≧', '⋉', '✷', '⊛', '⥽', '♢', '⟆', '⦿', '⊕', '⊚', '⨅', '♺', '⟒', '⨂', '⊖', '⥾', '≊', '⋄', '⥮', '⋑', '⥫', '⊝', '⋓', '✵', '⊘', '⧫']

plaintext = {symbol: letter for letter, symbol in zip(alphabet, syms_26)}

def decode(cipher, plaintext):
    decoded_text = ""
    for char in cipher:
        if char in plaintext:
            decoded_text += plaintext[char]
        else:
            decoded_text += char
    return decoded_text

ciphertext = "⥾⋄⥽⥾≧⋄⥽ ≧⨂⊛ ⥮⊖♺⊝⥽ ⋑⦿⥽ ⥽⨂⊕⟆⟒≧ ⋉⊘ ⊕⨂⊝⥽⥮⋑⊕⟆≧⋑⊕⨂⟆ ⨂⥽⋓ ⊚⥫⨂✷⋑⊕⊖⨂⥮. ✵-⟒≧⋄⨅⥽⊛ ♢⊕⨂⊛⊕⨂⟆⥮ ⥮⊖⊖⨂ ⊕⨂ 7 ≧⨂⥮⋓⥽⋄⥮ ⋉⥽✷⨅⊖⨂. ⦿7✷⋑♢{✷⋄⊘⥾7!✷_⟒⊘$⋑3⋄1⥽⥮_4⋄⥽_⟒3@⨂7_70_⋉3_✷⋄4✷⨅3⊛!}"

flag = decode(ciphertext, plaintext)

print("Output:", flag)
```

```bash
└─$ python3 decode.py
Output: prepare and solve the enigma by investigating new junctions. 
x-marked findings soon in 7 answers beckon. 
h7ctf{cryp7!c_my$t3r1es_4re_m3@n7_70_b3_cr4ck3d!}
```

Flag: `H7CTF{cRyp7!c_mY$t3r1es_4re_m3@n7_70_b3_cR4ck3d!}`

### RatedR

Here is another interesting challenge that revolves around the vulnerabilities of the `rand()` function and exploiting weak PRNGs.

"Enjoy the phase, as the journey is far more enjoyable than the destination." - SSR

Author: **`Abu`**

Given: `cert.pem` - `cipher` - `exploit`

```bash
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b'REDACTED'

timestamp = int(time.time())
random.seed(timestamp)

key = bytes([random.randint(0, 255) for _ in range(16)])
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(flag, 16))

print(f"Ciphertext: {ciphertext.hex()}")

Ciphertext: 3623a842948087c389b66d45226da8643f12a9372cca6b1ffd4dea706e4e5cdd08ed7ab059823236106c1e4c92a8b80e

--
MIID/DCCAuSgAwIBAgIUWQiXKiqLN6d7oFewOO53yeP1DjAwDQYJKoZIhvcNAQEL
BQAwUjELMAkGA1UEBhMCSU4xEzARBgNVBAgMClRhbWlsIE5hZHUxEDAOBgNVBAcM
B0NoZW5uYWkxDjAMBgNVBAoMBUg3VGV4MQwwCgYDVQQDDANBYnUwHhcNMjQwOTE0
MDUxNTU3WhcNMjUwOTE0MDUxNTU3WjBSMQswCQYDVQQGEwJJTjETMBEGA1UECAwK
VGFtaWwgTmFkdTEQMA4GA1UEBwwHQ2hlbm5haTEOMAwGA1UECgwFSDdUZXgxDDAK
BgNVBAMMA0FidTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANap7zzh
PkkPr0bUVLGpm/Uo0wKcYxKBVlAA3WURdkAOynabJxwELW3zvGdgIO7a/jj4lBY/
m6BqIOjvEJKTxwqf/q+vKJU2ts4f/DWgeMCOL+yVaVroXoTa+Tn9noBtRVsAh8Oo
2aKL+BUU3O9YnUWO5LOkIeqHgBF7/E4yZkLMD3zA0JoIfuiAVePEqdbXjb4jPngp
62Z8+GTozkX4iTe6ubdBb1+HMYo8ulKInwKxQYCrVninfNP31+k0TVakNIm6vB8T
dlVGXHea5SwjBp1WEfvnYqn1I6F1HlhE54ZyGYCygnGpvK8BNOJu8jkPxObSSqN9
4s00x+a5yZC3GPcCAwEAAaOByTCBxjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwFAYDVR0RBA0wC4IJaDd0ZXguY29tMHAGCisGAQQB1nkCAQEEYgxgVEc4
c0lIUm9aU0J6WldWa0lHOW1JSEpoYm1SdmJXNWxjM01nZDJGeklHSnZjbTRnYVc0
Z2RHaGxJR1ZoY214NUlHWnZjblJ1YVdkb2RDQnZaaUJUWlhCMFpXMWlaWEl1MB0G
A1UdDgQWBBQisOQr0VuZpgMEmiUjdR2turyIzDANBgkqhkiG9w0BAQsFAAOCAQEA
Hv0k1R+EMf7nsxlmg3+6oEMq/G5uNew624IB+EcXMlYH0C0vjZAbOP57DVmBgEQa
wiatl2bB56PllVDjYDpZi4yKKdD3gPletNBuA9KDpBv53HRx70qCXaorgcBB9VbC
zEhE8BdMXYcJiJawFfMMbJI/GREG0M2HVBMwmu92COSMHO8pJ1zHufHTS1s3EpYp
8hlrQjlV9aIyq8UDN0JeAp42VS/1HrBdcCZPX6IVNlB8nxAkksSfX70aogXssMoV
cViLfdNWbde1TeSUuSnyG65v6l/NQq/kyFNbwNU2JOYUOkCBkzYnZYrE653CvqrH
JCH3gzpg5vGpqnfLmP/39w==
--
```

Flag: `H7CTF{s0m37h1ng_s0_r@ndom_1s_n$ver_re@l}`

### **勝つ**

I choose a lazy person to do a hard job. Because a lazy person will find an easy way to do it.

Author: **`Abu`**

Given: `topsecret.zip`

[gpp-decrypt | Kali Linux Tools](https://www.kali.org/tools/gpp-decrypt/)

```bash
chal version="1.0" encoding="utf-8" Groups
clsid="31256937-E816-4b4c-9934-544FC6024026"><User clsid="(DF5F1855-51E5-4d24-881A-D9BDE98BA1D1)" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" id="(EF57DA28-5F69-4530-A59E-AAB585782190]"Properties action="U" newName" fullName="" description=""
cpassword="edBSH0whZLTjt/QS9FeIcJ83mjWA9Bgw9guk0hJ0dcqh+ZGMeX0sQbCpZ3xUjTLfCuNH8pG5a5VYdYw/Ng1VmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="@" userName="active
Groups>

cpassword="qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80"
```

Yo, there is actually quite an amusing story behind this `GPP[Group Policy Preferences]`, 

<aside>
💡

Imagine you’re the boss of a big company, and you have a bunch of computers that need to do specific things.

Now, instead of running around to each computer and setting everything up one by one (which would take forever!), you have a magic tool called “Group Policy Preferences” or GPP.

GPP is like your super assistant that helps you tell all the computers what to do, like where to put files, which programs to use, and what settings to follow. It’s like giving a secret code to all your computers so they know how to work together like a well-oiled team

</aside>

Credits - 

[Unwrapping GPP: Exposing the cPassword Attack Vector using Active (HTB Machine)](https://n1chr0x.medium.com/unwrapping-gpp-exposing-the-cpassword-attack-vector-using-active-htb-machine-4d3b97e0ac43)

Initial idea, create a folder structure similar to the original one found in SYSVOL, including all necessary directories before and after it. Inside this folder, place the `Groups.xml` file, which contains a `cpassword` field that the user needs to decrypt using the known key provided by Microsoft. Once the folder structure is ready, compress the entire directory into a zip file and secure it with a password derived from one of the last entries in `rockyou.txt`.
This way, I believe more people will get to know about the GPP vulnerability and a basic zip brute-forcing exercise. 

{{< figure src="10.png" alt="p4" >}}

```bash
└─$ cat secret_key
4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
```

Since this is the 32-byte key that was **inadvertently** leaked by Microsoft, the cipher is a AES-256 one and since we use ECB for this, we don’t have to worry about the IV.

```bash
SYSVOL/
└── domain/
    └── Policies/
        └── {GUID}/
            └── Machine/
                └── Preferences/
                    └── Groups/
                        └── Groups.xml
```

```bash
<?xml version="1.0" encoding="UTF-8"?>
<GroupPolicy>
    <Groups>
        <User>
            <Properties action="U" name="Administrator" cpassword="7dd6f0e338410b65387afc4d97bf19e78bb7b1d5092f4d17c706536dcfd792a6fc2cf74ea712aa73a3ad882a0faeeb5d" />
        </User>
    </Groups>
</GroupPolicy>

```

Flag: `H7CTF{m1cR0s0f7_r3@!!Y_d1d_F_7h1s_%p}`

Work-To-Be-Done.

## Reverse

### Eich

"Technology is only as good as the people behind it" - Brendan Eich

Author: **`Abu`**

Given: `shutthefrontdoor - trap`

[JSFuck - Write any JavaScript with 6 Characters: []()!+](https://jsfuck.com/)

Work-To-Be-Done.

Flag: `H7CTF{wh@_1N_7h3!r_r1gh7_m1nd_r@v3r$es_j@v4$scr!pt_L0LL!}`

### **Horcrux**

"Yer a wizard Harry" ― Rubeus Hagrid

Author - **`Abu`**

Given: `Horcrux`

```bash
└─$ file Horcrux
Horcrux: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=669dd367f1879be5971ec69b269bae13e5a713e9, for GNU/Linux 3.2.0, not stripped
```

Work-To-Be-Done.

Flag: 

```bash
Part 1 (Caesar Cipher Decrypted): H7CTF{
Part 2 (Base64 Decoded): %n0w!ng
Part 3 (XOR Cipher Decrypted): a$#emblY_
Part 4 (Rail Fence Cipher Decrypted): m4k3$_
Part 5 (Reverse Cipher Decrypted): ev5ry7h1ng_
Part 6 (ROT13 Cipher Decrypted): 0p3n_
Part 7 (Vigenère Cipher Decrypted): $0urce!}
```

### Hykes

"If you change the way you look at things, the things you look at change" - Wayne Dyer

Author: `Abu`

Work-To-Be-Done.

Flag: `H7CTF{1f_y0u_c4n7_f1y_7h3n_run_1f_y0u_c4n7_run_w41k_1f_y0u_c4n7_w41k_cr4w1_8u7_8y_411_m34n5_k33p_m0v1n6}`

## Open Source Intelligence

### Strike

`Description`: 

The author embarked on their CS50 journey last fall, and for their first project, they ventured onto a public programming site. The key to uncovering the hidden flag lies in the username they used in the past.

P.S. There are a ton of ways to solve this challenge so keep digging.

Author: **Abu**

First of all making this particular repository private as it take it right to the reward LOL. But there are other projects that are lying around, I guess even LinkedIn should be having the project list.

{{< figure src="11.png" alt="p4" >}}

Also, this LinkedIn project also takes the user straight into it.

{{< figure src="12.png" alt="12" >}}

Here is the a probable approach that the users could take. Finding the previous username from a part commit in the profile repository. 

{{< figure src="13.png" alt="13" >}}

In the comments of the Profile Repo, there is another hint for the challenge.

In the first commit of the Profile Repository there is a comment. But like I said, there are so many ways to solve this. LinkedIn, Lichess, people basically dug up my whole life for this challenge LOL. Scary AF.

[Commit Link](https://github.com/AbuCTF/AbuCTF/commit/d6bd8d9aae096af14fd63ec2ad314f6ec6692745)

{{< figure src="14.png" alt="14" >}}

Work-To-Be-Done.

[scratch.mit.edu](https://scratch.mit.edu/projects/873905829/)

Shout-out to `Pamdi` for blooding and finding an intended method.

{{< figure src="15.png" alt="15" >}}

Flag: `H7CTF{0N3_0f_7H3_6R3473$7_pr0gr4mm!n6_C0ur$3s_7h3re_1$!}`

### **Sins of the Shepherd**

A renowned investigator is unraveling the chilling mystery of a Korean pastor from Gardena, California, who murdered his family before taking his own life. But this case runs deeper—clues point to sensitive information hidden within the church's official website. Uncover the digital secrets the pastor left behind and help the investigator solve the case.

Can you find the username and password buried in the shadows.

Flag Format: H7CTF{username_password}

Authors: **`MrGhost, Abu`**

[DKPC.org](https://www.dkpc.org/files/config/ftp.config.php2)

{{< figure src="19.jpeg" alt="p4" >}}

Username: `anttisco`

Password: `Gil224224`

{{< figure src="16.png" alt="16" >}}

Flag: `H7CTF{anttisco_Gil224224}`

Work-To-Be-Done.

Here’s another site with everything open to the world. Was thinking to make this a challenge but there was already quite a few OSINT challenges so dropped.

[Plataforma](https://plataformalocadora.com.br/config/databases.yml)

Password: `afit918273` 

Flag: `H7CTF{afit918273}`

### **Kernel**

The Linux kernel repository is secured with a code **1646891026**. Uncover the exact sequence of this code to reveal the reward.

Flag Format: `H7CTF{RepoID_ForkNumber}`

Author: **`Abu`**

The ID is pretty straight forward, but the fork is dynamic, so I have a work-around, finding out the earliest site save to the `Internet Archive`, and finding the fork of that time.

Turns out the first save was on March 10, 2022 exactly matching the UNIX timestamp.

[WayBack Machine](https://web.archive.org/web/20220310054346/https://api.github.com/repos/torvalds/linux)

Which was `41873`.

Flag: `H7CTF{2325298_41873}`

## Web

### NoPaste

"If you spend too much time thinking about a thing, you'll never get it done. Paste it up, cut it out, and just do it" — Unknown

[Link](https://paste.h7tex.com/)

Author - **`Abu`**

Bypassing the Paste Restriction after looking at the obfuscated JavaScript with the payload `bypass123` , we use the console to bypass the restriction or even doing the same in Burp does the job.

[HTML Code Encryptor from ISDN*tek](https://www.isdntek.com/tagbot/encryptor.htm)

Payload: `document.getElementById('challengeInput').value = 'bypass123';`

{{< figure src="17.png" alt="p4" >}}


Flag: `H7CTF{h@ck_th3_sy$t3m}`

## Miscellaneous

### **QRco**

A seemingly innocuous QR code holds the key to a puzzle concealed in plain sight. Your quest begins with the scan of a code that unveils a document shrouded in mystery.

Author: **`SHL`**

Given: `QRco.jpg`
In this challenge, you are presented with a **QR code** that leads to a Google Drive link containing a **PDF** with a list of numbered entries, each associated with random strings of letters and symbols. Additionally, **ArUco markers** are embedded within the QR code image, making them visually apparent. You must extract these ArUco markers, find their IDs, and then use the PDF to map the corresponding letters. These letters, when assembled, form a **Base64 string**, which, when decoded, reveals the flag.

**Walkthrough**:

**Step 1: Scanning the QR Code**:

- When participants scan the QR code, they are directed to a **Google Drive link** that contains a PDF file.
- This PDF file lists numbers from **1 to 1000**, each associated with random strings of characters.
- This is a key part of the challenge as the ArUco marker IDs found later will correspond to these numbered entries in the PDF.

**Step 2: Identifying the ArUco Markers**:

- You will quickly notice that **ArUco markers** are embedded within the QR code image itself. These markers are visibly placed and relatively easy to detect.
- To extract the ArUco marker IDs, you can use **OpenCV** and Python. Here is a sample script for detecting the ArUco markers:

```python
import cv2
import numpy as np
import time

# Define ArUco dictionary types
ARUCO_DICT = {
    "DICT_4X4_50": cv2.aruco.DICT_4X4_50,
    "DICT_4X4_100": cv2.aruco.DICT_4X4_100,
    "DICT_4X4_250": cv2.aruco.DICT_4X4_250,
    "DICT_4X4_1000": cv2.aruco.DICT_4X4_1000,
    "DICT_5X5_50": cv2.aruco.DICT_5X5_50,
    "DICT_5X5_100": cv2.aruco.DICT_5X5_100,
    "DICT_5X5_250": cv2.aruco.DICT_5X5_250,
    "DICT_5X5_1000": cv2.aruco.DICT_5X5_1000,
    "DICT_6X6_50": cv2.aruco.DICT_6X6_50,
    "DICT_6X6_100": cv2.aruco.DICT_6X6_100,
    "DICT_6X6_250": cv2.aruco.DICT_6X6_250,
    "DICT_6X6_1000": cv2.aruco.DICT_6X6_1000,
    "DICT_7X7_50": cv2.aruco.DICT_7X7_50,
    "DICT_7X7_100": cv2.aruco.DICT_7X7_100,
    "DICT_7X7_250": cv2.aruco.DICT_7X7_250,
    "DICT_7X7_1000": cv2.aruco.DICT_7X7_1000,
    "DICT_ARUCO_ORIGINAL": cv2.aruco.DICT_ARUCO_ORIGINAL,
    "DICT_APRILTAG_16h5": cv2.aruco.DICT_APRILTAG_16h5,
    "DICT_APRILTAG_25h9": cv2.aruco.DICT_APRILTAG_25h9,
    "DICT_APRILTAG_36h10": cv2.aruco.DICT_APRILTAG_36h10,
    "DICT_APRILTAG_36h11": cv2.aruco.DICT_APRILTAG_36h11
}

# Choose ArUco dictionary type
aruco_type = ARUCO_DICT["DICT_5X5_1000"]

# Load the dictionary and parameters
arucoDict = cv2.aruco.getPredefinedDictionary(aruco_type)
parameters = cv2.aruco.DetectorParameters()

image_path = "QRco.jpg"  # Replace this with the path to your input image
image = cv2.imread(image_path)

if image is None:
    print("Error: Image not loaded correctly.")
    exit()

# Detect ArUco markers in the image
corners, ids, rejected = cv2.aruco.detectMarkers(image, arucoDict, parameters=parameters)

# Copy the original image for visualization
imageCopy = image.copy()

# Draw detected markers
if ids is not None:
    cv2.aruco.drawDetectedMarkers(imageCopy, corners, ids)

# Optionally, draw rejected markers
showRejected = True
if showRejected and rejected is not None and len(rejected) > 0:
    cv2.aruco.drawDetectedMarkers(imageCopy, rejected, borderColor=(100, 0, 255))

output_image_path = "output_with_markers.jpg"
cv2.imwrite(output_image_path, imageCopy)

cv2.imshow("Detected ArUco Markers", imageCopy)
cv2.waitKey(0)
cv2.destroyAllWindows()

print(f"Processed image saved as: {output_image_path}")

```

After running the code you get the following output

{{< figure src="18.jpg" alt="p4" >}}

Now, by reading the numbers column by column from left to right and then refer it to the pdf you get the following:

```python
    548: 'SDdD',
    729: 'VEZ7',
    176: 'UVJ4',
    839: 'NHJV',
    612: 'YzBf',
    493: 'RW4x',
    984: 'Z200',
    251: 'fQ=='
```

Which when combined together gives you 

```python
SDdDVEZ7UVJ4NHJVYzBfRW4xZ200fQ==
```

which is a base64 string. Finally you decode this to get the flag.

> Flag:  `H7CTF{QRx4rUc0_En1gm4}`
> 

---

[SHL’s Blogs](https://www.notion.so/SHL-s-Blogs-e4bc2fca021f4d88850420aa5ce4223e?pvs=21)

A lot of work to be done here, will keep updating here if possible or the Authors will be posting individually. Thank to all the people from around the world for playing. Really glad, we had the chance to conduct a CTF at the International level. Hope to improve and make it more interesting for the players next time. Until Then. Keep Hacking. Peace.
