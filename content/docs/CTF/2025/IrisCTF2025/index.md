---
title: "IrisCTF2025"
description: "Migrated from Astro"
icon: "article"
date: "2025-01-30"
lastmod: "2025-01-30"
draft: false
toc: true
weight: 999
---

# IrisCTF 2025

## Rip Art

Description: I can't believe I forgot to save my art!

Given: `rip-art.tar.gz`

Author: `skat`

We’ve been given a `pcapng` file, just as a heads up, the difference between a `pcap` and a `pcapng` (**PCAP Next Generation**) is more extensible and portable than PCAP and has a more flexible file structure. The first things first, let’s open it up in `Wireshark`. Looking at the protocol hierarchy, we can see that it’s completely USB protocol.

{{< figure src="image%200.png" alt="image.png" >}}

At first, let’s do some reconnaissance with both Wireshark and `tshark`[CLI alternative].

[B-Roll](https://www.youtube.com/watch?v=-KLEDJjXjrM)

### Reconnaissance

Here I check for the different lengths involved in the USB capture.

```
└─$ tshark -r art.pcapng -T fields -e frame.len | sort -n | uniq -c
  27335 64
   6333 71
   3684 72
  10986 74
   6332 722
```

To understand the reasoning behind this is, we need to understand about `HID` [**Human Interface Device**], it’s a type of computer device usually used by humans that takes input from or provides output to humans.

In case of the mouse data is captured, it’s transferred in HID with about 4 bytes [32 bits]. The first byte represents buttons pressed. `0x00` is no buttons pressed, `0x01` indicates left button pressed, and `0x02` indicates right button pressed. The second byte is a signed byte, where the highest bit is the sign bit. When positive, it represents how many pixels the mouse has moved horizontally to the right. When negative, it shows how many pixels it has moved horizontally to the left. The third byte, like the second byte, represents an offset that moves vertically up and down.

Now in case of keyboard data, it’s about 8 bytes [64 bits], and the keystrokes occur at the 3rd bytes, enough of the rant, let’s get back on topic. Now that we have all the lengths in the file, we can analyze them one by one.

As for the `64` length packets, which account for more than half of the packets, we encounter `URB_INTERRUPT IN` and `URB_BULK OUT` but the absence of HID-specific data and the `Data length [bytes]: 0` suggests it is a control packet or placeholder with no actual payload being transferred.

Next up, let’s take the `722` length packets, in contrast to the 64 length packets, we see a huge size of payload being transferred, but we also notice it’s been padded heavily. let’s compare two of packets of same length to try and check out what type of payload in being transferred.

{{< figure src="image%200-5.png" alt="image.png" >}}

Used an online tool to do the job. Turns out only 3 bytes from the same indices keep changing and the others act like a padding around them.

{{< figure src="image%201.png" alt="image.png" >}}

[Diffchecker - Compare text online to find the difference between two text files](https://www.diffchecker.com/text-compare/)

One thing to note is that there’s always a response for this packet with the ones in the 64 length packets, which replies with an empty payload, kind off like cancelling each other. I’m guessing this much some sort of a connection handshake of sorts.

{{< figure src="image%202.png" alt="image.png" >}}

Now comes the more interesting packets, `71`, `72` and `74`. As for `71`, it’s a `URB_INTERRUPT_IN` data packet, and it’s the response to a packet from host [which is packet with length 64], in this example, initially we see a request from packet 2 [host] to the response in packet 5 with destination [`1.7.1`] which is the `HID` device, and this happens all the way till the end, also notice packets 3 and 4, which are requests and responses that (kinda) cancel each other out, and this pattern also continues until the end. Finally also notice the leftover capture data is the same [`13050100010100`] for all the packets with length 71.

{{< figure src="image%203.png" alt="image.png" >}}

Onto to the next one, packets with length `72` comes as a response to the host. Now the source [`1.13.1`] comes with the leftover capture data that changes for every response, that should hit a bulb. 💡 Note that the source [1.13.1] only occur for 8 times.

{{< figure src="image%204.png" alt="image.png" >}}

The main source of the the packets with length 72 comes from the source, `1.3.2`. Looking at the leftover capture data, comes to 8 bytes with padding, remove the padding my comparing the packets, we are left with `4 bytes` of data and with the information in hand, we can come to a conclusion that we’re looking at `Mice HID capture data!`

{{< figure src="image%205.png" alt="image.png" >}}

Next, we come onto the final packets in question, `74` length one with the primary source being `1.14.1`, which again comes as a response to the host. 

{{< figure src="image%206.png" alt="image.png" >}}

Looking at the capture data, we see 10 bytes with padding, remove padding results in a payload of 8 bytes, that means another form of mice data that needs some manipulating and filtering to extract. [Mice seems so weird to type HAHA]

Cool stuff, now that we know we have two different HID device captures, let’s promptly go ahead and extract them payloads. I know this type of reconnaissance is tedious and hard, but this is how packet captures are meant to be analyzed, now that’s an advice for me first HAHA.

### Extracting HID

As for the first part of mice data capture, we can go ahead and use a tool to extract stuff.

[USB-Mouse-Pcap-Visualizer](https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer)

Now, I’m able to explain stuff like this in a structed manner because I’ve gone through the solve process that involves a lot of hiccups and struggles before figuring out something, this applies to general CTF challenge solving, go through the process, only then a proper writeup will hit like a truck, that’s where true learning happens.

As for using the tool, follow the steps in the `GitHub`, but before you install, make sure you’re in a virtual environment, and a heads up the `poetry install` command sure takes a while to run.

```
usage: usb-mouse-pcap-visualizer.py [-h] -i INPUT_FILE -o OUTPUT_FILE
```

Here, you input our file and define an output `.csv` file, the csv file can then be visualized by `assets/index.html`, or try it [online](https://usb-mouse-pcap-visualizer.vercel.app/).

{{< figure src="image%207.png" alt="image.png" >}}

 That gives us a part of the flag, but this is to be expected as we have another source [`1.14.1`] to analyze. Now after some real solid effort on googling this and that stuff, we come across this writeup, which referenced another writeup, gem of a writeups these [credits to the `authors`].

[CTFtime.org / Affinity CTF 2019 - Quals / Pharmacist Nightmare / Writeup](https://ctftime.org/writeup/16410)

[BITSCTF – Tom and Jerry (50 points)](https://blogs.tunelko.com/2017/02/05/bitsctf-tom-and-jerry-50-points/)

At first, we extract the packets with source `1.14.1`, in Wireshark with a simple filter of `usb.src == "1.14.1”` and or with `tshark`.

```bash
tshark -r art.pcapng -Y "(frame.len == 74)" -e "usb.capdata" -T fields > data.txt
```

In this case, we use the length as the filter as both the source and the length can be used interchangeably. To proceed here is an example for reference to put things in place.

{{< figure src="image%208.png" alt="image.png" >}}

Since our data.txt has all the bytes clobbered together, we need to segregate every byte with a `:` for further parsing, magic with `sed`.

```bash
sed 's/../&:/g; s/:$//' data.txt > format.txt
```

Back on track, 💡 Note: the representation is in little endian format, so we need to extract positions 3,4 for X and 5,6 for Y but first we must somehow swap those bytes, again with the `awk` magic.

```bash
awk -F: '{x=$3$4;y=$5$6}{z=$7}$1=="02"{print x,y,z}' format.txt > hex.txt
```

Now that we’ve extracted the `coordinates`, let’s swap them.

```python
from pwn import *
for i in open('hex.txt').readlines():
    ii = i.strip().split(' ')
    x = int(ii[0], 16)
    y = int(ii[1], 16)
    z = int(ii[2], 16)
    if z > 0:
        print(u16(struct.pack(">H", x)), u16(struct.pack(">H", y)))
# python3 solve.py > coordinates.txt
```

The code is essentially reading hexadecimal values from `hex.txt`, packing them into 16-bit integers in big-endian format, and then printing those integers if the condition is met (`z > 0`).
Condition is done so that if `z > 0` signifies an event or change (like a movement or button press), it makes sense to filter out packets where no such event occurs (`z == 0`).

At last we have the coordinates that tracks the mice data. To visualize, we need a tool called `gnuplot`, which helps with plotting stuff, like `Desmos` but CLI version.

Also, since I’m in `WSL2`, I have this GUI rendering issue, so I’ll have to save it as an image. Open up gnuplot and use the following commands.

```bash
set terminal pngcairo
set output 'mirror.png'
plot 'coordinates.txt'
```

That gives up a mirrored image, but is the case in all the write-ups references, maybe it’s the way the **coordinates** (such as mouse movements or button presses) are being captured has an inherent mirroring effect. Using `ImageMagick` reverse the image, will get us the other part of the flag.

```bash
convert mirror.png -flop flag.png
```

{{< figure src="image%209.png" alt="image.png" >}}

Flag: `irisctf{usb_comm_protos_got_nothing_on_u}`

`Resources`

[USB - CTF Wiki EN](https://ctf-wiki.mahaloz.re/misc/traffic/protocols/USB/)

[Human interface device](https://en.wikipedia.org/wiki/Human_interface_device)

[www.usb.org](https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf)

[CTFtime.org / Affinity CTF 2019 - Quals / Pharmacist Nightmare / Writeup](https://ctftime.org/writeup/16410)

[BITSCTF – Tom and Jerry (50 points)](https://blogs.tunelko.com/2017/02/05/bitsctf-tom-and-jerry-50-points/)
