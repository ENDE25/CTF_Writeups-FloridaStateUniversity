This document contains the write-ups for the three challenges of **Assignment 5**.

| Problem ID | Lab Name               | Captured Flag                                  | Steps                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------- | ---------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Problem 1  | Xperience              | `fsuCTF{p1ca55o_w0u1dv3`<br>`_l0v3d_m5pa1n7}`  | - **Analyze Disk Image:** Decompress the `.7z` file and identify the Virtual Hard Disk (`.vhd`) as a Windows XP installation.<br>- **Locate User Data:** Mount the disk and navigate to `C:\Documents and Settings\daniel` to find a `README.rtf` mentioning a "masterpiece".<br>- **Trace Recent Activity:** Check the `Recent` folder for shortcuts, identifying `masterpiece.bmp.lnk` which pointed to a file in the `Application Data` folder.<br>- **Extract Flag:** Open the recovered `masterpiece.bmp` image with a viewer to reveal the flag. |
| Problem 2  | Jaws                   | `fsuCTF{Y0ur3_G0nn4_N33d`<br>`_A_Bi6g3r_8o47}` | - **Traffic Analysis:** Open the `jaws.pcap` file in Wireshark and filter for suspicious HTTP GET requests to the IP address `178.63.67.153`.<br>- **Identify Encoding:** Notice a repetitive UUID-like path with a `?q=` parameter containing Base64-encoded strings.<br>- **Reconstruct Data:** Manually extract and concatenate the Base64 values from the query parameters in chronological order.<br>- **Decode Flag:** Use CyberChef to decode the full Base64 string to reveal the flag.                                                        |
| Problem 3  | Whats the title again? | `fsuCTF{1_d0n7_w4n7_t0`<br>`_pl4y_4nym0r3}`    | - **Process Identification:** Use Volatility on the memory dump (`whats_the_title_again.raw`) to identify active processes like `wmplayer.exe`.<br>- **Inspect Command Line:** Check `windows.cmdline` to see the media player's initial file, though the default sample song was a distraction.<br>- Locate the song title written in leetspeak within the memory strings                                                                                                                                                                             |




---

### ==PROBLEM 1== - Xperience
This challenge provides us with a file named `xp_smol.7z`.

#### 1. Analysis
We started by decompressing the file using `7z x xp_smol.7z`, which gave us `xp_smol.vhd`. Running the `file` command confirmed this was a **Virtual Hard Disk**.

![[Pasted image 20260220010016.png]]

This meant it was likely to be a file system, so I mounted the disk on a Linux machine to explore the directories. 

> To mount it, I first needed to identify which partition contained the data, which I determined using `virt-filesystems -a xp_smol.vhd`. The output showed that the data was located in `sda1`.

```bash
mkdir /mnt/xp_disk
sudo guestmount -a xp_smol.vhd -m /dev/sda1 --ro /mnt/xp_disk
```

> I mounted it in **read-only mode** (`--ro`) to avoid altering the evidence.

After mounting the drive and listing its content, I immediatly realized I was looking at a **Windows XP** installation. 

![[Pasted image 20260220011404.png|480]]

In XP, user data isn't in `C:\Users`, but in `C:\Documents and Settings`. I identified a user named **daniel**.

*Inside Daniel's Desktop, I found an `openssl.zip` containing a full OpenSSL Git repository. After searching the code and Git history for hidden clues, I discovered it was just a distraction and not related to the actual solution.*

I decided to stop analyzing the source code and instead look through the rest of Daniel’s files to see what else was there.

The first interesting thing I could find was a file called `README.rtf`, located in Daniel's `"My Documents"` folder.  Inside, I found a note from Daniel explaining the challenge’s lore:

![[Pasted image 20260220014910.png]]

Since Daniel didn’t remember where he saved his masterpiece, I decided to check his activity.

On Windows XP, the `Recent` folder stores `.lnk` (shortcut) files for every document or application the user has opened. I navigated to `/mnt/xp_disk/Documents and Settings/daniel/Recent` and found a shortcut named `masterpiece.bmp.lnk`.

![[Pasted image 20260220015300.png|420]]

#### 2. Solution Strategy
A `.lnk` file is more than a shortcut; it contains the absolute path to the target file. Even if the file is moved or "lost," the shortcut reveals where it was intended to be. I used `strings` on the shortcut and saw it pointed to 
`C:\Documents and Settings\daniel\Desktop\masterpiece.bmp`, but the file wasn't there.

![[Pasted image 20260220015558.png|450]]

#### 3. Execution and Flag
Since the "masterpiece" wasn’t on the desktop, I assumed it was elsewhere, so I used the `find` command to scan the entire disk:

![[Pasted image 20260220015942.png|650]]

Apparently if a program like Paint crashes or is closed unexpectedly, it can save recovery data or temporary files in the `Application Data` folder.

I first tried using `strings` on the BMP file, but found nothing. After some research, I learned that BMP is a Windows image format that stores pictures as a grid of pixels, so I simply opened it with an image viewer and that revealed the flag.

![[Pasted image 20260219001306.png|250]]

Flag: `fsuCTF{p1ca55o_w0u1dv3_l0v3d_m5pa1n7}`

---

### ==PROBLEM 2== - Jaws
The challenge provides a single file named `jaws.pcap`. The prompt states that a network has been infiltrated and the traffic was captured to find evidence. The goal is to analyze the packet capture, identify the malicious activity, and recover the flag.

#### 1. Analysis
Since I was given a `.pcap` file, I knew right away that this was a network traffic capture. To see what was happening inside the network, I opened the file using **Wireshark**.

I began with a preliminary visual inspection, scrolling through the packets to see which protocols were most frequent. I immediately noticed a mix of **TCP, DNS, and HTTP**.
- I first checked the **DNS** queries to see if there were any "weird" domains, but it just looked like standard queries.
- I then looked at the **HTTP** traffic. I noticed that among the regular traffic, there was a repetitive pattern of requests that didn't look like normal browsing.

![[Pasted image 20260220200415.png]]

Every few packets, a specific internal host was reaching out to the same external destination. I saw that all these suspicious requests were directed to the IP address **178.63.67.153**. I applied a filter for that specific address: `http && ip.addr == 178.63.67.153`.

Once filtered, I could see that the traffic consisted of dozens of GET requests to a very long, unique UUID-like path: `/1a7b92af-e58d-41c2-9493-edcdb4066a8c`. Every request ended with a different value for a parameter named `q`.

![[Pasted image 20260220202257.png]]


#### 2. Solution Strategy
I focused on the `?q=` parameter. I noticed that the values ended with an `=` sign. This is a very common indicator of **Base64 encoding**.

To see if I was on the right track, I decided to manually test the first few values using an online decoder:
1. `ZnM=` -> `fs`
2. `dUM=` -> `uC`
3. `VEY=` -> `TF`

When I put those together, I got `fsuCTF`. It was clear that the flag was being sent piece by piece through these query parameters.

The plan now was to:
1. Extract all the strings from the `q=` parameter in chronological order.
2. Concatenate them into one long string.
3. Decode the final string from Base64 to reveal the flag.

#### 3. Execution and Flag
Since the number of packets wasn’t excessive, I manually extracted the values of the `q` parameter and concatenated them into a single string:

`ZnM=dUM=VEY=e1k=MHU=cjM=X0c=MG4=bjQ=X04=MzM=ZF8=QV8=Qmk=Nmc=M3I=Xzg=bzQ=N30=`

I then pasted the reconstructed string into CyberChef, decoded it, and obtained the flag.

![[Pasted image 20260220204528.png|350]]

Flag: `fsuCTF{Y0ur3_G0nn4_N33d_A_Bi6g3r_8o47}`

---

### ==PROBLEM 3== - Whats the title again?
The goal of this challenge is to recover the title of a song that a user was listening to based on a provided memory dump. The instructions mentioned that the flag is not wrapped in the standard `fsuCTF{}` format inside the memory, so we must identify the string and wrap it ourselves.

The provided files for this challenge were:
- `memory.vmem`
- `what.raw`
- `whats_the_title_again.raw`

Although three memory images were provided, I chose to focus my analysis on `whats_the_title_again.raw`, as its filename directly matched the title of the challenge.

#### 1. Analysis
I began by seeing what was happening on the machine at the time of the dump so I listed the active processes.

`vol -f whats_the_title_again.raw windows.pslist`

![[Pasted image 20260220215540.png]]

I spotted two processes that seemed likely to correspond to programs being used by the user.
- `wmplayer.exe` (PID 2004): The Windows Media Player.
- `notepad.exe` (PID 2276): A text editor.

I decided to see what was in the Notepad. To analyze the process (PID 2276), I dumped its memory using Volatility:

```bash
vol -f whats_the_title_again.raw windows.memmap --pid 2276 --dump
```

I then ran `strings` on it to extract readable strings from the dump and search for references to the term “flag”.

```bash
strings -e l pid.2276.dmp | grep -i "flag"
```

![[Pasted image 20260220222317.png|600]]

The output showed several lines that confirmed I was looking in the right places, but it told me that the actual flag was hidden elsewhere and I shouldn't expect it to look like a flag.

I shifted the focus to understanding how the processes were being used. I started by checking the command line arguments, as this could reveal file paths or specific tracks being opened by a media player.

```bash
vol -f whats_the_title_again.raw windows.cmdline
```

The output for `notepad.exe` showed nothing interesting but the output for `vmplayer.exe` showed it had been launched with the file `Sleep Away.mp3`.

![[Pasted image 20260220224539.png]]

At first I thought this could be the song that the user was listening to but the flag `fsuCTF{Sleep Away.mp3}` wasn't accepted as a solution. After some research I learned that **"Sleep Away"** by Bob Acri is a famous default sample song included with Windows 7.

I suspected the player might have started with this song, but the user likely changed it later. I needed a way to see what the Media Player was currently showing to the user. 

Typically, a media player's song title appears in the window’s title bar, so I proceeded to attempt its recovery.

#### 2. Execution and Flag
I tried to use the `windows.windows.Windows` plugin to list window titles, but I hit a technical wall: the plugin failed, stating it only supports x64 versions of Windows.

I decided to search the entire memory dump for the string "Windows Media Player", as window titles for this app usually follow the pattern: `[Song Title] - [Artist] - Windows Media Player`.

![[Pasted image 20260220223753.png|550]]

This time, the song name appeared in leetspeak, which confirmed that we had successfully identified the flag.

Flag: `fsuCTF{1_d0n7_w4n7_t0_pl4y_4nym0r3}`

