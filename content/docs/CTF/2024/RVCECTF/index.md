---
title: "RVCECTF"
description: "Migrated from Astro"
icon: "article"
date: "2024-06-25"
lastmod: "2024-06-25"
draft: false
toc: true
weight: 999
---

Commencing our first CTF Write-Up. We’re excited to share the write-ups from the recent RVCExIITB CTF event at R. V. College of Engineering. We post the solves of whatever we managed to do within the time-frame of the CTF. Hope to post the ones we didn't manage to solve as well. Best Ways To Learn. Without further ado, let’s dive right in!

```
Authors: AbuCTF, Rohmat
```

## Forensics

Starting off with Forensics cause it’s everyone’s favorite haha. More like it’s the easiest.

{{< figure src="sweat.gif" alt="sweat" >}}

### **Operation Woofenstein**

**Description**: Your beloved canine companion Agent Snuggles, has gone missing! You need to find him. Here’s a picture of him. Remember snuggles is the key, even when you may not be able to see him.

**Given**: `snuggles.jpg`

**Author**: Ananya Bhat

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics$ file snuggles.jpg
snuggles.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=1], baseline, precision 8, 6260x4170, components 3
```

After trying out other standard stuff like `strings`, `binwalk` and so on. `steghide`revealed a zip file underneath.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics$ steghide extract -sf snuggles.jpg
Enter passphrase:
wrote extracted data to "snuggle.zip".
```

unzipping it, we get

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics$ unzip snuggle.zip
Archive:  snuggle.zip
   creating: snuggles/
   creating: snuggles/notsnuggles/
   creating: snuggles/aerosol/
   creating: snuggles/snuggles/
   creating: snuggles/snuggles/snuggless/
  inflating: snuggles/snuggles/snuggless/flag.jpg
 extracting: snuggles/snuggles/snuggless/...
   creating: snuggles/./
 extracting: snuggles/./...
```

Dang, that’s it? or so I thought. Things were just starting to get serious. We move.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics/snuggles/snuggles/snuggless$ exiftool flag.jpg
ExifTool Version Number         : 12.40
File Name                       : flag.jpg
Directory                       : .
File Size                       : 100 KiB
File Modification Date/Time     : 2024:05:16 01:10:56+05:30
File Access Date/Time           : 2024:06:21 18:13:37+05:30
File Inode Change Date/Time     : 2024:06:25 11:55:49+05:30
File Permissions                : -rwxrwxrwx
Error                           : File format error
```

File format error huh. Quick google to find out the magic numbers of a jpg file.

{{< figure src="p2.png" alt="p2" >}}

Using `hex-edit` to fix those errors.

{{< figure src="p3.png" alt="p3" >}}

Now, that we have the image corrected, let’s see what it holds.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics/snuggles/snuggles/snuggless$ file flag.jpg
flag.jpg: JPEG image data, JFIF standard 1.02, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 2010x1988, components 3
```

{{< figure src="p4.jpeg" alt="p4" >}}

But before we move on, there’s a hidden detail within the zip file. If we look closely,

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics/snuggles/snuggles/snuggless$ ls -la
total 104
drwxrwxrwx 1 abu abu    512 May 16 01:12 .
drwxrwxrwx 1 abu abu    512 Jun 21 18:14 ..
-rwxrwxrwx 1 abu abu     72 May 16 01:03 ...
-rwxrwxrwx 1 abu abu 102864 Jun 25 12:02 flag.jpg
```

See the file named `…` , sneaky way to hide a file. But if you use windows or WSL2. Basically any GUI.

{{< figure src="p5.png" alt="p5" >}}

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics/snuggles/snuggles/snuggless$ cat ...
good job!
here's a treat -  /folders/1lJwLRBWnnDQdayQAgmlJyXTkTaRfI5WR
```

We have a link, that looks very much like a Drive link. But straight-up doing `https://drive.google.com/folders/1lJwLRBWnnDQdayQAgmlJyXTkTaRfI5WR` doesn’t work. 

Little more look up on how Drive links works, we get

`https://drive.google.com/drive/folders/1lJwLRBWnnDQdayQAgmlJyXTkTaRfI5WR`.

{{< figure src="p6.png" alt="p6" >}}

We find an ISO Image. Interesting.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Forensics$ file finaldiscimage.iso
finaldiscimage.iso: ISO 9660 CD-ROM filesystem data 'CDROM'
```

Mount the ISO.

Turns out it’s a Linux-Based system. Going straight into the `/home` directory.

```bash
abu@Abdur-PC:/mnt/iso/home$ ls -R -l
.:
total 12
dr-xr-xr-x 2 root root 2048 May 20 21:27 bazing
dr-xr-xr-x 2 root root 2048 May 20 21:27 bazinga
dr-xr-xr-x 2 root root 2048 May 20 21:26 santa
dr-xr-xr-x 4 root root 2048 May 20 21:28 snuggles
dr-xr-xr-x 2 root root 2048 May 20 21:26 viciousmoon
dr-xr-xr-x 2 root root 2048 May 20 21:27 whales

./bazing:
total 0

./bazinga:
total 0

./santa:
total 0

./snuggles:
total 4
dr-xr-xr-x 2 root root 2048 May 20 21:28 flag
dr-xr-xr-x 2 root root 2048 May 20 21:32 nottheflag

./snuggles/flag:
total 0

./snuggles/nottheflag:
total 562
-r--r--r-- 1 root root 575116 May 16 22:43 flag.tiff

./viciousmoon:
total 0

./whales:
total 0
```

Even though, it’s in the `/nottheflag` directory, we find a `flag.tiff` file. Which at first we thought was nothing special. But there is a twist.

The flag is hidden in the background of the file. You could use `ImageMagick` or `Aperisolve` to reveal the flag.

[Aperi'Solve](https://www.aperisolve.com/)

Here the is command for `ImageMagick` in PowerShell.

```powershell
magick .\flag.tiff `
-colorspace HSL `
-channel G -separate +channel `
-threshold 50% -negate `
-compose over `
-alpha off `
.\finalFlag.tiff
```

{{< figure src="woofFlag.png" alt="woof" >}}

Flag: `flag{snugGles_found_h4ppy}`

## **Miscellaneous**

### **Time rewind tactics**

**Description**: Time is not your enemy but rather an ally to find the board. Analyze the board, unmake the moves, rewrite history to achieve the desired outcome

**Given**: `message.txt`

**Author**: Ananya Bhat

A pretty straight-forward challenge, where the the message given is a cipher. Putting the cipher into a Cipher-Identifier like `dcode` . We get to know the type. Then it’s just decoding to get the flag.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ cat message.txt
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.++++++.-----------.++++++.++++++++++++++++++++.--------.-----------.-----------------------------------------------------.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++.--------.----------------------------------------------------.++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.---------------.++++++++++++++++++++++++.-----------------------------------------------------------------------.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.-----------------------------------------.++++++++++++++++++++++++.-----.-----------------------------.---------------.++++++++++++++++++++++++++++++++++++++++++++.---------------.++++++++++++++++++++++++++++++++++.-----------------------------------.++++++++++++++++++++++++++++++++++++++.-----------------.-----.-------------------------------------------.++++++++++++++++.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++.
```

[Cipher Identifier](https://www.dcode.fr/cipher-identifier)

{{< figure src="p7.png" alt="p7" >}}

Try out the other ones, it’s `Brainfuck` .

<aside>
💡 Brainfuck (or BF or Brainfuck) is a minimalist programmation language that uses only eight commands to manipulate memory and perform operations.

It takes its name from two words brain and fuck, that refer to a kind of major frustration for your brain (or cerebral masturbation). LOL.

</aside>

{{< figure src="p8.png" alt="p8" >}}

**Flag**: `flag{sh3ld0n_w0uLd_B3_PrOud_4D}`

### **Wallet Recovery - Weaponization**

**Description:** 

I have found an bitcoin wallet which is **10 years** old. It's my dad's wallet. The main problem is that he forgot the secure password which he created from `Roboform` Password Generator. I told this to my friend, and he told me that one hacker recently posted a video how he managed to crack the password of roboform and recovered millions from wallet. Can you help me to get the video?

Flag Format: `flag{youtube_url}` eg: `flag{https://www.youtube.com/watch?v=dQw4w9WgXcQ}` or `flag{https://youtu.be/dQw4w9WgXcQ}`

**Author** - WR4TH

This was another easy challenge, where the solution is to find the link that fits the description of the challenge. I came across this video a while back, and it instantly hit me. Great documentary. Had fun watching it.

[I hacked time to recover $3 million from a Bitcoin software wallet](https://youtu.be/o5IySpAkThg?si=aHJr-zrgOt4YDzOJ)

Flag: `flag{https://youtu.be/o5IySpAkThg?si=aHJr-zrgOt4YDzOJ}`

### RAW

**Description:** 

Your task is to unravel the covert message concealed by a RAW agent. Delve into intercepted communications, analyze an ocean of datadump and decipher the hidden codes to unveil the critical intelligence intended for Indian counterparts. Can you crack the code and reveal the clandestine message?

**Given**: `Ocean.zip`

**Author** - Bipin Raj

Really interesting challenge, that unfortunately wasn’t able to solve during the CTF. Solved it the next day. Pain.

By the way, `wget` doesn’t work for retrieving files in this CTF, which is a bummer.

```bash

abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ zipinfo Ocean.zip
408409 files, 8568101 bytes uncompressed, 8568097 bytes compressed:  0.0%
```

Turns out this was zip bomb. FYI.

<aside>
💡 In computing, a zip bomb, also known as a decompression bomb or zip of death (ZOD), is a malicious archive file designed to crash or render useless the program or system reading it. The older the system or program, the more likely it is to fall for it. It is often employed to disable antivirus software, in order to create an opening for more traditional malware.

</aside>

Well, writing a script to find the common sizes in the zip file, We got this idea as I tried unzipping the file for the first time. There were a lot of 21s.

```python
import zipfile
from collections import Counter

def function(zipPath):
    file_sizes = []

    with zipfile.ZipFile(zipPath, 'r') as zipRefs:
        for fileInfo in zipRefs.infolist():
            if not fileInfo.is_dir():
                file_sizes.append(fileInfo.file_size)

    sizeCounter = Counter(file_sizes)
    commonSize = sizeCounter.most_common()

    return commonSize

zipPath = '/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous/Ocean.zip'
commonSize = function(zipPath)

for size, count in commonSize:
    print(f"Size: {size} bytes, Count: {count}")
```

**Output**: 

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ python3 common.py
Size: 21 bytes, Count: 407992
Size: 15 bytes, Count: 2
Size: 99 bytes, Count: 1
Size: 48 bytes, Count: 1
Size: 23 bytes, Count: 1
Size: 17 bytes, Count: 1
Size: 20 bytes, Count: 1
Size: 32 bytes, Count: 1
```
Printing out the contents of these files,

```python
import zipfile

def function(zip_path):
    filesNot21 = []

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for fileInfo in zip_ref.infolist():
            if fileInfo.file_size != 21 and not fileInfo.is_dir():
                filesNot21.append(fileInfo.filename)

    return filesNot21

def print_file_contents(zip_path, file_list):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for file_name in file_list:
            with zip_ref.open(file_name) as file:
                print(f"Contents of {file_name}:")
                print(file.read().decode('utf-8'))
                print("-" * 40)

zip_path = '/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous/Ocean.zip'

filesNot21 = function(zip_path)

print_file_contents(zip_path, filesNot21)
```

**Output**:

```python
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ python3 read.py
Contents of Ocean/chall169/file69:
aHR0cHM6Ly9kcml2ZS5nb29nbGUuY29tL2RyaXZlL2ZvbGRlcnMvMXkzaVBVUmNvekRFbld3bUZEYU9sQlRVVU52NVlTX3Ut==

----------------------------------
Contents of Ocean/chall213/file158:
flaghttps://www.youtube.com/watch?v=dQw4w9WgXcQ

----------------------------------
Contents of Ocean/chall300/file104:
flagdontgiveup

----------------------------------
Contents of Ocean/chall348/file106:
flaggity flag

----------------------------------
Contents of Ocean/chall405/file39:
did u try '{' as well?

----------------------------------
Contents of Ocean/chall405/file52:
fake flags much?

----------------------------------
Contents of Ocean/chall439/file449:
AHjsdggdlllVGSHYAID

----------------------------------
Contents of Ocean/chall461/file108:
flag{r3d_heRR1n9s_4re_aNn0yinG}

----------------------------------
```

Slight troll at the end, giving out a fake flag at the end. Ofcourse, I came to know that after trying it out LOL. And please not a Rick-Roll again haha.

The juicy stuff is in the base-64 string. Let’s go.

```python
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ python3
Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> print(base64.b64decode("aHR0cHM6Ly9kcml2ZS5nb29nbGUuY29tL2RyaXZlL2ZvbGRlcnMvMXkzaVBVUmNvekRFbld3bUZEYU9sQlRVVU52NVlTX3Ut==").decode('utf-8'))
https://drive.google.com/drive/folders/1y3iPURcozDEnWwmFDaOlBTUUNv5YS_u-
```

Oh, a drive link. Opening the link, we find 2 files. `info` and `transmission.jpg`

{{< figure src="p9.png" alt="p9" >}}


The `info` file seemingly holds nothing, but when you try highlighting it. You find something.

{{< figure src="p10.png" alt="p10" >}}

It’s has to related to some `steghide`. So we try it.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Miscellaneous$ steghide extract -sf transmission.jpg
Enter passphrase:
wrote extracted data to "secret.txt".
```

Boom. Extracted `secret.txt` , which seems to contain another drive link. But it needs some tune-up. Here is the correct way to get to the link.

`https://drive.google.com/file/d/1hK3tV5PPtdOwUujHOqQOgl1NI015GpNU`

{{< figure src="p11.png" alt="p11" >}}

Huh, it seems to be encrypted. Turning to the OG `John The Ripper` to brute-force this zip file.

```bash
┌──(kali㉿kali)-[~/Documents/CTF/rvCTF]
└─$ zip2john agentnotebook.zip > hash.txt
┌──(kali㉿kali)-[~/Documents/CTF/rvCTF]
└─$ john --wordlist=~/Downloads/rockyou.txt --format=zip hash.txt 
Using default input encoding: UTF-8
Loaded 43 password hashes with 43 different salts (ZIP, WinZip [PBKDF2-SHA1 128/128 SSE2 4x])
Loaded hashes with cost 1 (HMAC size) varying from 0 to 2002
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
topgun           (agentnotebook.zip/agentnotebook/.git/HEAD)     
topgun           (agentnotebook.zip/agentnotebook/.git/objects/06/11094751a34eb58304585586f22ff4f2c251c3)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/cb/8df2583e8ac52e4fe8cd0b2b24093761718ec6)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/sendemail-validate.sample)                                                 
topgun           (agentnotebook.zip/agentnotebook/.git/objects/5c/4a0e4526606123ea4ea932cfe61bbe2990b927)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/applypatch-msg.sample)                                                     
topgun           (agentnotebook.zip/agentnotebook/.git/logs/refs/heads/master)                                                          
topgun           (agentnotebook.zip/agentnotebook/.git/objects/ba/7a55e5ff8655d913f4ab0008feb5ace847a482)                               
topgun           (agentnotebook.zip/agentnotebook/.git/COMMIT_EDITMSG)                                                                  
topgun           (agentnotebook.zip/agentnotebook/.git/objects/78/5d67f5556861bbd09ec58de88c6951cf2e63bf)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/e5/6d4d3ec8a2dd07a28af9c62f52cc9c1cc7b632)                               
topgun           (agentnotebook.zip/agentnotebook/.git/refs/heads/master)                                                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/d3/5aa0a5bf35a9bd59c85ea8ba78332d7fb8c790)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/4f/da7dec868ba8a29700a30bac03b90ede27be9b)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-commit.sample)                                                         
topgun           (agentnotebook.zip/agentnotebook/.git/objects/d0/ef70c9382d765ac75bf16a3e454f97512f063b)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/post-update.sample)                                                        
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-push.sample)                                                           
topgun           (agentnotebook.zip/agentnotebook/.git/objects/4a/c14fb6cb1b81647d490a61d189046b231c5bc8)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/b9/4108b737a5c7c288df13dd8ad8a22ce799aa09)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/f0/c2f2e91db329896a643b70ef43e2803849b2cd)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/prepare-commit-msg.sample)                                                 
topgun           (agentnotebook.zip/agentnotebook/.git/objects/dd/427cea5c4a24ad28d352a1391b7a7cfcf457ec)                               
topgun           (agentnotebook.zip/agentnotebook/important.txt)     
topgun           (agentnotebook.zip/agentnotebook/.git/description)     
topgun           (agentnotebook.zip/agentnotebook/.git/index)     
topgun           (agentnotebook.zip/agentnotebook/.git/FETCH_HEAD)     
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/push-to-checkout.sample)                                                   
topgun           (agentnotebook.zip/agentnotebook/.git/info/exclude)     
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-applypatch.sample)                                                     
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/commit-msg.sample)                                                         
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/update.sample)                                                             
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-merge-commit.sample)                                                   
topgun           (agentnotebook.zip/agentnotebook/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/63/2038de8b94e0399a313ece7bf3be6de4d79382)                               
topgun           (agentnotebook.zip/agentnotebook/.git/config)     
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-receive.sample)                                                        
topgun           (agentnotebook.zip/agentnotebook/.git/objects/7d/855b6e3cd5a1b92ffe8ae364a6877888df4780)                               
topgun           (agentnotebook.zip/agentnotebook/.git/logs/HEAD)     
topgun           (agentnotebook.zip/agentnotebook/.git/objects/19/7de13837ff3f378f0a54f3766991fb8c39aeb2)                               
topgun           (agentnotebook.zip/agentnotebook/.git/objects/ca/268a31d4c25973efed16d1ff6f7ccfc81d1216)                               
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/fsmonitor-watchman.sample)                                                 
topgun           (agentnotebook.zip/agentnotebook/.git/hooks/pre-rebase.sample)                                                         
43g 0:00:00:22 DONE (2024-06-23 00:48) 1.922g/s 274.6p/s 11810c/s 11810C/s newzealand..horoscope
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Oh, `topgun` . Maverick is one of the best movies I watched. Visual master-class. Anyways we use that to extract the zip file. It gives us a `important.txt` file.

```bash
┌──(kali㉿kali)-[~/Documents/CTF/rvCTF]
└─$ cat important.txt 
Secrecy is of utmost priority in covert communications and we take secrecy very seriously
I have only one message for all of you hackers - HISTORY repeats itself.
trace your steps and find em' all 
```

Since, the other files are a `.git` repository. It hints on using commit history in `Git`.

For some reason when I try to unzip in Kali, it gives me unsupported error.

```bash
skipping: agentnotebook/.git/index  unsupported compression method 99
```

Probably, something silly that I could’ve missed.

Anyways I used `7z` in Windows to extract the zip folder.

{{< figure src="p12.png" alt="p3" >}}

Put the PowerShell into work.

```powershell
PS C:\Documents3\CyberSec\CTF2\RVCTF\Finals\forensics\agentnotebook\.git> git log
commit 785d67f5556861bbd09ec58de88c6951cf2e63bf (HEAD -> master)
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:41:32 2024 +0530

    commit6

commit 4fda7dec868ba8a29700a30bac03b90ede27be9b
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:40:52 2024 +0530

    commit5

commit dd427cea5c4a24ad28d352a1391b7a7cfcf457ec
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:40:18 2024 +0530

    commit4

commit f0c2f2e91db329896a643b70ef43e2803849b2cd
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:39:52 2024 +0530

    commit3

commit cb8df2583e8ac52e4fe8cd0b2b24093761718ec6
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:38:59 2024 +0530

    commit2

commit ba7a55e5ff8655d913f4ab0008feb5ace847a482
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:38:17 2024 +0530

    commit1
```

Then we just view the commits to get the flag. Beautiful.

```powershell
PS C:\Documents3\CyberSec\CTF2\RVCTF\Finals\forensics\agentnotebook\.git> git log --pretty=format:"%H" | ForEach-Object {
>>     $commit = $_
>>     Write-Host "Commit: $commit"
>>     git show $commit
>>     Write-Host "--------------------------------------------------------"
>> }
Commit: 785d67f5556861bbd09ec58de88c6951cf2e63bf
commit 785d67f5556861bbd09ec58de88c6951cf2e63bf (HEAD -> master)
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:41:32 2024 +0530

    commit6

diff --git a/important.txt b/important.txt
index 632038d..197de13 100644
-----------------------------------------------------
Commit: 4fda7dec868ba8a29700a30bac03b90ede27be9b
commit 4fda7dec868ba8a29700a30bac03b90ede27be9b
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:40:52 2024 +0530

    commit5

diff --git a/important.txt b/important.txt
index d0ef70c..632038d 100644
-----------------------------------------------------
Commit: dd427cea5c4a24ad28d352a1391b7a7cfcf457ec
commit dd427cea5c4a24ad28d352a1391b7a7cfcf457ec
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:40:18 2024 +0530

    commit4

diff --git a/important.txt b/important.txt
index 0611094..d0ef70c 100644
-----------------------------------------------------
Commit: f0c2f2e91db329896a643b70ef43e2803849b2cd
commit f0c2f2e91db329896a643b70ef43e2803849b2cd
Author: BipinRajC <bipinraj.4604@gmail.com>
Date:   Mon Apr 15 00:39:52 2024 +0530

    commit3

diff --git a/important.txt b/important.txt
index 5c4a0e4..0611094 100644
-----------------------------------------------------
```

Flag: `flag{th3_j0urn3y_t0_b3_a_R4W_ageNt_i5_n0T_aN_ea5Y_on3}`

## **Steganography**

### **MOV or Coldplay?**

**Description**: In the face of an impending English literature exam and a tempting Coldplay concert the next day, Alex, a music-loving high school student, struggles to focus on studying Shakespeare's "The Merchant of Venice." Turning to ChatGPT for help, he seeks a quick summary of the play to expedite his preparation. With newfound clarity, Alex races against time to strike a balance between academic obligations and his passion for music, hoping to conquer the exam and still make it to the concert.

**Author** - Bipin Raj

**Given:** `chall.txt`

Opening the text in `VSCode` , you see a lot of white-spaces. OK, so it’s `stegsnow`.

{{< figure src="p13.png" alt="p13" >}}

But it’s password protected. Reading the paragraphs properly, reveals a cool password. password: `operaoctopus`.

```powershell
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Stego$ stegsnow -C -p operaoctopus chall.txt
Now, that you're past the first layer, you're gonna find a mysterious and weird hidden text file, make of it what you will https://cybersharing.net/s/6945fb8e0e93bdb6
```

Extracting from `stegsnow`, reveals this link.`https://cybersharing.net/s/6945fb8e0e93bdb6`.

{{< figure src="p14.png" alt="p14" >}}

We reveal a `hidden.txt`. Interesting.

```
Dylan says pursuit of adrenaline must be never-ending
shout (at) Dylan
Phil says but that's the fun
say (yes) Phil 
bobby says C
(for)crime is continuous
universe is resplendent
shout bobby 
say crime (shouldn't be)
(but) whisper universe (is beautiful)
dobby says d
say dobby
peter says p
whisper peter
(but) whisper universe (is beautiful)
life is hard
say life (is what? is hard)
georgia says Y
say georgia(it's just like that)
nature says R
whisper nature 
beauty is wilderness
whisper beauty
bobby (again) says C
(so just) shout bobby
(we're such insignificant beings in this beautiful universe, just live it bobby)
secret says k
whisper secret
(finally) the truth is great
whisper the truth
```

Weird. I wasn’t able to figure out what the hidden thing was. Credits: `Bipin Raj`. The Author later on told it was an `Esolang` called as `Rockstar` Programming Language. Going ahead and decoding this from the online decoder. Using the below link. We get the flag. YAY. New thing learned !

[Rockstar : Try It](https://codewithrockstar.com/online)

```
pursuit of adrenaline must be never-ending
but that's the fun
C
0
1
d
p
1
4
Y
R
0
C
k
5
Program completed in 42 ms
```

**Flag**: `flag{C01dp14YR0Ck5}`

### **The Forgotten Binary**

**Description**: William’s friend is a tech nerd who was helping him boot a new linux based OS in his PC and after everything was done, he told William that he’d forgotten to install ‘rm’ on his new linux distro and provided him the binary to make his life easier. (William was clueless)

**Author**: Bipin Raj

**Given**: `rm`

First things first.

```bash
abu@Abdur-PC:/mnt/c/Documents3/CyberSec/Tempo/RVCTF/Stego$ file rm
rm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e8b7e344eda821652030f20cd66139fba719927b, for GNU/Linux 3.2.0, stripped
```

Damn, an ELF file in a steganography category. Crazy. Really unique choice of questions. 

By the way, if you go ahead and try to execute the file, it actually does `rm` on a file. No progress on this. So here’s after the CTF ends. Credits: `Bipin Raj`.

So by comparing both the `rm` binaries, we find out the binary contains hidden data similar to LSB Steganography. Compare them by using the command below,

```bash
diff <(hexdump -C /bin/rm) <(hexdump -C ./rm)
```

Researching about Steganography for binaries. We find out about this.

[Steg86](https://github.com/woodruffw/steg86)

Which is a technique to hide data within a binary, Remember it’s for a 64-bit executable.

**`steg86`** takes advantage of one of x86's encoding peculiarities: the R/M field of the Mod R/M byte
You could install it using `Cargo`, Cargo is **a build tool and package manager for Rust that's used to manage Rust projects**.

```bash
┌──(kali㉿kali)-[~/Documents/CTF/rvCTF/stego]
└─$ cargo install steg86  
    Updating crates.io index
  Downloaded steg86 v0.2.1
  Downloaded 1 crate (17.9 KB) in 1.58s
  Installing steg86 v0.2.1
    Updating crates.io index
```

```bash
┌──(kali㉿kali)-[~/Documents/CTF/rvCTF/stego]
└─$ ./steg86 extract rm > flag.txt
			1n5piR3d_bY_R1SV_b1n4ri3s_5te5aN0gr4pHy
```

Flag- `rvcectf{1n5piR3d_bY_R1SV_b1n4ri3s_5te5aN0gr4pHy}`

{{< figure src="continue.jpg" alt="Continue" >}}
