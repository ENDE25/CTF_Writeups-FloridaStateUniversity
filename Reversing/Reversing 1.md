This document contains the write-ups for the three challenges of **Assignment 6**.

| Problem ID | Lab Name            | Captured Flag                                         | Steps                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------- | ------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Problem 1  | Nuclear Pasta       | `fsuCTF{sp4ghett1_c0d3_15_a_`<br>`d3fens3_mech4n1sm}` | - **Identify Encryption:** Analyze the binary to find a "spaghetti code" convert function, which is actually a simple XOR cipher using the key `0xBB`.<br>- **Extract Ciphertext:** Use a debugger like GDB to extract the target encrypted bytes (`ct`) from memory.<br>- **Decrypt:** Perform a bitwise XOR operation between each extracted byte and `0xBB` to reveal the flag.                                                                       |
| Problem 2  | Old School Gauntlet | `fsuCTF{b3tt3r_7h4n_cry5t41_`<br>`4rm0r}`             | - **Step 1:** Set a breakpoint after the Parent Process check and overwrite the buffer at `$rbp-0x120` with a null byte to hide GDB.<br>- **Step 2:** Reach the Ptrace check and use the jump command to force execution to the success address at `main+1237`.<br>- **Step 3:** Reach the Time check and use jump to skip to `main+1358`, bypassing the 1-second limit.<br>- **Step 4:** Inspect the memory at `$rbp-0x250` to read the decrypted flag. |
| Problem 3  | Upper Management    | `fsuCTF{5ti11_b3tter_7h4n_`<br>`73ch_supp0r7}`        | - **Determine Length:** Use `ltrace` to find that the program requires an input length of exactly 38 characters.<br>- **Symbolic Execution:** Because the transformation function is too complex to reverse by hand, use the angr library in Python to define the input as symbolic variables.<br>- **Configure the solver** to find a path that reaches the "Good enough" success message while avoiding the "Wrong" failure path.                      |

---

## ==PROBLEM 1== - Nuclear Pasta
In this challenge, we are given a single Linux binary called `nuclear_pasta`.

#### 1. Analysis
The first thing I did was check what kind of file I was dealing with using the `file` command.

![[Pasted image 20260224231310.png]]

The fact that it is **not stripped** will make reading the code easier sinces the developer left the function and variable names inside the binary.

I gave the file execution permissions (`chmod +x nuclear_pasta`) and ran it to see how it behaves:

![[Pasted image 20260224231502.png|400]]

Apparently, the program just checks the flag. I enter a string, and it tells I’m wrong.

I ran `strings` to see if the flag was just hidden in the text. I didn't find the flag, just the success/failure messages.

![[Pasted image 20260224232650.png|320]]

I uploaded the file to **Dogbolt.org**. I checked different outputs, but **Hex-Rays** gave the most readable code. I found two important functions: `main` and `convert`.

- Inside `main`, I saw this:
	![[Pasted image 20260224233223.png]]
	1.  It asks for my input.
	2.  It uses a loop to change every letter I type using the `convert` function.
	3.  It compares my modified input with a variable called `ct` using `strcmp`.

- I then looked at the `convert` function: 
	![[Pasted image 20260224233716.png]]
	I realized the `do-while` loop is a distraction. The condition `!(v4 % v3)` is only true once. The only important part is `a1 ^= 0xBB`. This means the "spaghetti code" is just a simple **XOR cipher** with the number **0xBB**.

#### 2. Solution Strategy
I tried to use `strings` to find the secret `ct`, but it was not there. This is because `ct` is not a "string" in the code, but a list of bytes in the memory.

To get those bytes, I used **GDB**. I knew the variable was named `ct` because the program was not stripped.

![[Pasted image 20260224234256.png]]

> The command `x/48xb` allows us to retrive 48 bytes in hex

Now I have the "encrypted" bytes from the memory and I know the secret key is `0xBB`. The theory of XOR is: if `P ^ Key = C`, then `C ^ Key = P`. So, I just need to take every byte from `ct` and do XOR with `0xBB`.

![[Pasted image 20260224235434.png|250]]

#### 3. Execution and Flag
Before doing everything, I wanted to be sure that my XOR theory was correct. I took the first four bytes from the `ct` variable in GDB and calculated them manually:

- **0xdd** ⊕ **0xbb** = `0x66` ('f')
- **0xc8** ⊕ **0xbb** = `0x73` ('s')
- **0xce** ⊕ **0xbb** = `0x75` ('u')
- **0xf8** ⊕ **0xbb** = `0x43` ('C')

The result is the start of the flag format so I knew I was on the right path.

I wrote a Python script to decrypt all the bytes I found in GDB:

```python
ct_bytes = [
    0xdd, 0xc8, 0xce, 0xf8, 0xef, 0xfd, 0xc0, 0xc8, 0xcb, 0x8f, 0xdc, 0xd3, 0xde, 0xcf, 0xcf, 
    0x8a, 0xe4, 0xd8, 0x8b, 0xdf, 0x88, 0xe4, 0x8a, 0x8e, 0xe4, 0xda, 0xe4, 0xdf, 0x88, 0xdd, 
    0xde, 0xd5, 0xc8, 0x88, 0xe4, 0xd6, 0xde, 0xd8, 0xd3, 0x8f, 0xd5, 0x8a, 0xc8, 0xd6, 0xc6
]

key = 0xbb
flag = ""

for b in ct_bytes:
    flag += chr(b ^ key)

print(f"Flag: {flag}")
```

I executed the script and it returned the flag.

Flag: `fsuCTF{sp4ghett1_c0d3_15_a_d3fens3_mech4n1sm}`

---

### ==PROBLEM 2== - Old School Gauntlet
In this challenge we are provided with an ELF binary executable named `gauntlet`. When executed normally, it displays a welcome message and immediately begins a series of "checks" before finishing.

![[Pasted image 20260223215150.png]]

The program claims to decrypt a flag at a specific memory address, but it finishes execution without actually printing it.

#### 1. Analysis
To understand the internal logic, I loaded the binary into **GDB** (`gdb -q ./gauntlet`) and examined the assembly code of the `main` function using `disas main`.

I observed three distinct blocks of code that functioned as protections or checks:

1. **Parent Process Check:** 
	I observed calls to `getppid@plt` followed by `readlink@plt`. 
	
	*Calls `getppid` and stores the result in `ebx`*![[Pasted image 20260223220745.png]]
	*Builds the string `/proc/[PID]/exe`*![[Pasted image 20260223220931.png]]
	*The program then reads the symbolic link `/proc/[PID]/exe`.*![[Pasted image 20260223221517.png]]
	Later, I saw a call to `strstr@plt`, which suggests the program then scans the parent process name for specific forbidden strings.
	![[Pasted image 20260223221652.png]]

2. **Debugger Check (Ptrace):** 
	I found a call to `ptrace@plt`. Immediately after, the code compares the result (`rax`) with `-1` (`0xffffffffffffffff`).
	![[Pasted image 20260223221926.png]]
    If `ptrace` returns -1, it means the process is already being traced by a debugger. A conditional jump (`jne`) directs the flow to an exit routine if this check fails.

3. **Execution Time Check:** 
	I observed two calls to `time@plt` at different points in the execution. Between them, the code performs a subtraction (`sub`) and compares the result against `0x1` (1 second).
    If the execution takes longer than 1 second, the program jumps to a failure block.
	![[Pasted image 20260223222213.png]]	![[Pasted image 20260223222528.png]]

If any of these checks fail, the program skips the decryption logic or terminates.

>[!info] Integrity Variable
> Additionaly, a local variable at `[rbp-0x269]` serves as a cumulative XOR key for the final flag decryption. This variable is only updated if the previous checks are passed successfully:
>1. **1:** Increments by `1` after the Parent Check.
>2. **2:** Bitwise left-shifts by 4 (`shl 4`) after the Ptrace Check.
>3. **3:** Bitwise left-shifts by 2 (`shl 2`) after the Time Check.        
>
>*The final flag is decrypted using this variable. If the checks are bypassed using manual patching (like changing jumps to `NOP`), the variable never reaches the required value of 64, which results in an incorrectly decrypted flag*.
>
>![[Pasted image 20260223224246.png]]


#### 2. Solution Strategy
I will use **Dynamic Analysis** within GDB to bypass these checks at runtime.

My plan is to:
1. **Identify the critical decision points** (jumps) for each of the three protections.
2. **Manipulate the memory or registers** at runtime to trick the program into believing it is running normally, "bypassing" the gauntlet while keeping the decryption logic intact.

#### 3. Execution and Flag
I started the program with `start`. This pauses execution at the `main` function.

```bash
gef➤ start
```

**Step 1: Bypassing the Parent Check**
The first check reads the parent process name. Even if the system call succeeds, the buffer will contain ".../gdb", which triggers a detection mechanism later (a `strstr` search). To bypass this, I set a breakpoint at the instruction immediately _after_ the read is performed (`*main+861`).

```bash
gef➤ break *main+861
gef➤ continue
```

At this point, the buffer at `$rbp-0x120` contained the string ".../gdb". I wrote a `0` (null byte) to the beginning of this address. This makes the program read the string as empty.

```bash
gef➤ set {char}($rbp-0x120) = 0
```

**Step 2: Breakpoints**
With the first check neutralized, I set breakpoints at the remaining critical decision points (Ptrace and Time) and the finish line *(if I don't put the last one the program will finish and the RAM will be wiped before we can retrieve the flag)*.

```bash
gef➤ break *main+1182
gef➤ break *main+1303
gef➤ break *main+1647
```

**Step 3: Bypassing the Ptrace Check***
I continued execution until the Ptrace check.

```bash
gef➤ continue
```

`[ main+1182 ]` - GDB indicated the jump was `NOT TAKEN` (failure). 

![[Pasted image 20260223225545.png]]

I used the `jump` command to skip to the success address (`*main+1237`).

```bash
gef➤ jump *main+1237
```

**Step 4: Bypassing the Time Check**
`[ main+1303 ]` - Since I was manually stepping through the code, the execution time was much longer than the allowed 1 second, so the jump was `NOT TAKEN`. I forced the jump to the success address (`*main+1358`).

![[Pasted image 20260223231431.png]]

```bash
gef➤ jump *main+1358
```

**Step 5: Decryption**
`[ main+1647 ]` - Having successfully bypassed all three gates (Guardian, Ptrace, and Time), I inspected the stack memory at `$rbp-0x250` where the flag was constructed.

![[Pasted image 20260223232050.png]]

Flag: `fsuCTF{b3tt3r_7h4n_cry5t41_4rm0r}`

---

## ==PROBLEM 3== - Upper Management

In this challenge, we are presented with a Linux binary named `upper_management`. The prompt mentions a 3rd quarter IPO and a management team looking for a "brand new flag" to show off to investors. 

#### 1. Analysis
I started running `file` to understand what kind of file I was dealing with.

![[Pasted image 20260225000408.png]]

The word **"stripped"** means the developers removed all the function and variable names, so I won't see a clear `main()` function or helpful labels in the debugger.

Next, I checked for hardcoded strings using `String` but it didn't give any relevant information. I then tried running the binary and giving it a dummy input, and nothing interesting happened.

![[Pasted image 20260225000721.png|600]]

I tried using `ltrace` to see if the program used `strcmp` to compare my input against the real flag in memory.

![[Pasted image 20260225001029.png|600]]

I noticed that it calls `strlen` on my input but **never reaches a comparison function**. This suggested that the program first checks if the input length is correct. If it isn't, it just exits.

Since I couldn't see the symbols, I used **Dogbolt.org** to look at the decompiled code from Ghidra. I searched for the "Management" strings to find the main logic. I found a function that contained the following:

![[Pasted image 20260225002010.png]]

1. The input must be exactly **38 characters** long ($0x26$ in hex).    
2. The program iterates through each character and passes it to a function `FUN_004011d6` along with its index.
3. Looking into `FUN_004011d6`, it was a massive chain of XORs, additions, and shifts that seemed impossible to reverse by hand.
	![[Pasted image 20260225001815.png]]
4. Finally, the transformed string is compared against a hardcoded byte array (`local_c8`).

#### 2. Solution Strategy
I could have tried to rewrite the math function in Python and brute-force it character by character, but since I have access to Symbolic Execution tools like **angr**, I decided to use them instead.

What I am going to do is let angr analyze the program and automatically calculate the correct input. Instead of testing many possible values manually, I define the input as symbolic data and tell angr to find a path that reaches the `"Good enough"` message.

> Angr does not execute the program with real numbers at first. It treats the input as symbolic variables and tracks the conditions the program applies to them. Then it computes concrete values that satisfy all those conditions and make the program follow the desired execution path.

![[Pasted image 20260225002731.png|500]]

#### 3. Execution and Flag
I wrote a short Python script using the `angr` library. I defined the input as a symbolic variable of 38 bytes and told the solver to find a path that prints the success message while avoiding the failure message.

```python
import angr
import claripy

project = angr.Project('./upper_management')

flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(38)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

state = project.factory.entry_state(stdin=flag)

for c in flag_chars:
    state.solver.add(c > 32, c < 127)

simgr = project.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"Good enough" in s.posix.dumps(1),
              avoid=lambda s: b"Wrong" in s.posix.dumps(1))

if simgr.found:
    print("Flag:", simgr.found[0].posix.dumps(0).decode())
```

Running the script took about 15 seconds. The solver successfully navigated through all the XORs and additions to find the original characters.
![[Pasted image 20260225004800.png]]

I verified it by running the binary manually:

![[Pasted image 20260225004849.png]]

Flag: `fsuCTF{5ti11_b3tter_7h4n_73ch_supp0r7}`