This document contains the write-ups for the four challenges of **Assignment 3**.

| Problem ID | Lab Name | Captured Flag                                                                                                                            | Steps                                                                                                                                                                                                                                                                                                              |
| ---------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Problem 1  | Crazy    | `fsuCTF{I_W45_Cr4zy_0nc3_7h3y_10ck3d_`<br>`M3_In_4_R00m_4_Ru883r_R00m_4_Ru883r_`<br>`R00m_Fi113d_Wi7h_C7F_7h3_C7F_M4yd3_`<br>`M3_Cr4zy}` | - Identify Ruby ERB template engine<br>- Bypass output filtering using <% _erbout << ... %><br>- List server files and read the flag file<br>- Extract the flag from the rendered output                                                                                                                           |
| Problem 2  | Surfing  | `fsuCTF{w4v3_4_fl4g}`                                                                                                                    | - Identify XXE vulnerability in XML parser<br>- Use XXE to perform SSRF to internal service<br>- Target http://127.0.0.1:5001/<br>- Retrieve the flag from the internal server response                                                                                                                            |
| Problem 3  | l33t-44s | `fsuCTF{wh9_h057_4ny7h1ng_0n_pr3m_`<br>`wh3n_u_c0u1d_b3_1337}`                                                                           | - Analyze provided C source code<br>- Identify argument injection via `-e` option<br>- Execute system commands through backend binary<br>- Locate the flag file using command execution<br>- Dump file contents using `od -b` to avoid leet conversion<br>- Convert octal output back to ASCII to recover the flag |
| Problem 4  | fat_cat  | `fsuCTF{1f_1_f17s_1_5i7s}`                                                                                                               | - Review Express.js backend source code<br>- Identify impossible length condition for input<br>- Analyze `extended: true` URL encoding behavior<br>- Inject an object instead of a string<br>- Manually define a large `length` property<br>- Bypass the condition and receive the flag                            |

---

### ==PROBLEM 1== - Crzay
The challenge presents a simple web interface with an input field.

The page contains a small script that intercepts the form submission, encodes the user input into **Base64**, and redirects the browser to `/room?crazy=[<input>]`. Upon visiting this URL, the server displays a massive block of text repeating the input hundreds of times.

#### 1. Analysis
The initial analysis focuses on how the input is reflected. Since the response is massive and repetitive, I first check for **Cross-Site Scripting (XSS)**. However, I notice the header `x-xss-protection: 1; mode=block` is present.

![Pasted image 20260207035310.png](../_img/Pasted%20image%2020260207035310.png)

I suspect **Server-Side Template Injection (SSTI)**. This happens when an application embeds user input into a template string before rendering it. If I can inject an expression that the server evaluates, I can achieve **Remote Code Execution (RCE)**.

I begin by testing the most common template syntaxes.

| **Payload**  | **Result**                                          | **Analysis**                         |
| ------------ | --------------------------------------------------- | ------------------------------------ |
| `{{7*7}}`    | Literal `{{7*7}}`                                   | It is not Python or PHP              |
| `${7*7}`     | Literal `${7*7}`                                    | It is not Java or Mako               |
| `<%= 7*7 %>` | "I might be crazy but I still know how Ruby works." | The engine is identified as **Ruby** |
The fact that I receive a custom message instead of the result `49` indicates the presence of a Web Application Firewall (WAF) or a blacklist. The server detects the `<%=` tag (the "printing" tag in Ruby) and blocks the output.

#### 2. Solution Strategy
I need to find a way to execute code without triggering the blacklist. In Ruby's ERB engine, there are two main tags:
1. `<%= ... %>`: Executes code and prints the result
2. `<% ... %>`: Executes code but does not print anything

test the execution-only tag:
- **I send:** `<% 7*7 %>`
- **Result:** The "Crazy" text appears, but the spaces where my input should be are completely **empty**.

![Pasted image 20260207041639.png](../_img/Pasted%20image%2020260207041639.png)

This implies that the code is executing, but because I am not using the `=`, the result is not being sent to the page. 

>I find that ERB uses an internal variable called `_erbout`. This is a string buffer where all the HTML content is stored before being sent to the client. When a developer uses `<%= some_code %>`, the engine is actually executing `<% _erbout << (some_code).to_s %>`

To see the output, I will have to manually push data into the server's output buffer. I try to manually append a value to this buffer:
- **I send:** `<% _erbout << 7*7 %>`
- **Result:** The page is filled with the character **"1"**.

>**Why "1"?** I realize that in Ruby, when an Integer is appended to a String using the `<<` operator, it is often treated as an **ASCII value**. 7×7=49. In the ASCII table, the code **49** corresponds to the character **'1'**.

 This confirms I have direct access to the output buffer.

#### 3. Execution and Flag
Now that the filter can be bypassed by using `<% _erbout << ... %>`, I move toward looking for the flag. 

>I need to convert everything to a string using `.to_s` to avoid the ASCII conversion issue.

I use the `Dir` class to see what files are on the server.

*Payload:*
```ruby
<% _erbout << Dir["*"].to_s %>
```

*Output:*
![Pasted image 20260207042547.png](../_img/Pasted%20image%2020260207042547.png)

I use `File.read` to extract the content of the flag.

*Payload:*
```ruby
<% _erbout << File.read("flag.txt") %>
```

*Output:*
![Pasted image 20260207042854.png](../_img/Pasted%20image%2020260207042854.png)

Flag:  `fsuCTF{I_W45_Cr4zy_0nc3_7h3y_10ck3d_M3_In_4_R00m_4_Ru883r_R00m_4_Ru883r_R00m_Fi113d_Wi7h_C7F_7h3_C7F_M4yd3_M3_Cr4zy}`

---

### ==PROBLEM 2== - Surfing
The challenge presents a simple web application for a **Surfboard Billing Invoice**. The user is greeted with a form to enter a name, surfboard model, and quantity.

#### 1. Analysis
I started by inspecting the source code of the page. I noticed something relevant in the client-side logic. The form doesn't send a standard POST request. Instead, a script captures the input and wraps it into an **XML structure**, which is then encoded in **Base64** and sent to the endpoint `/process_invoice`.

![Pasted image 20260207053215.png](../_img/Pasted%20image%2020260207053215.png)

To see it I make a test request. After decoding, the payload sent is:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<invoice>
    <name>test</name>
    <model>Shortboard</model>
    <quantity>1</quantity>
</invoice>
```

Inside the HTML, I also found a developer comment that suggested that there is an internal service running on **port 5001** that is not accessible from the outside.
```html
<!--DELETE THIS COMMENT dev environ on port 5001 -->
```

#### 2. Solution Strategy
I started by checking if the XML parser on the server was vulnerable to **External Entities**. An XXE vulnerability occurs when an application parses XML input that contains a reference to an external entity, and the parser is misconfigured to resolve that entity.

The plan is to define a custom entity and see if I could read a local file like `/etc/passwd`. If the server returns the content of that file in the "Customer Name" field, It will mean it works.

I crafted a payload to read `/etc/passwd`.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<invoice>
    <name>&xxe;</name>
    <model>Shortboard</model>
    <quantity>1</quantity>
</invoice>
```

I encoded this in Base64 and sent it via a POST request.
![Pasted image 20260207054654.png](../_img/Pasted%20image%2020260207054654.png)

The result was empty. This might mean one of two things: either the `file://` wrapper is disabled, or the server is not showing the output of the entity.

Since the server didn't allow reading local files, I will use the XXE to perform a **Server-Side Request Forgery (SSRF)**. Since I know there was a dev environment on port 5001, I can define an entity that points to `http://127.0.0.1:5001/`. The server will then fetch the content of its own internal port and display it to me.

#### 3. Execution and Flag
I modified the payload to target the internal web server.

*Payload:*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:5001/">
]>
<invoice>
    <name>&xxe;</name>
    <model>Shortboard</model>
    <quantity>1</quantity>
</invoice>
```

Again, I encoded this in Base64 and sent it via a POST request.
![Pasted image 20260207055204.png](../_img/Pasted%20image%2020260207055204.png)

The internal service on port 5001 simply served the flag as its index page.

Flag:  `fsuCTF{w4v3_4_fl4g}`

---

### ==PROBLEM 3== - l33t-44s
The challenge presents a web-based "Leet-as-a-Service" tool. It allows users to input plaintext and convert it into leetspeak using a backend utility written in C. The challenge provides a web interface and a link to the open-source repository containing the C code.

#### 1. Analysis
The website consists of an input box for the `payload` and two checkboxes for "CTF Mode" (`-c`) and "Random Mode" (`-r`). Intercepting the traffic with ZAP Proxy, I saw that the form sends a POST request with two parameters: `payload` and `options`.

![Pasted image 20260207060624.png](../_img/Pasted%20image%2020260207060624.png)

I start by testing common web vulnerabilities. Since the app interacts with a backend binary, my first thought was **Command Injection**.

*Example:*
```
payload=test&options=-c;ls`
```

The result for all of my attempts is similar: `Your options look (';') malicious so I've blocked it.` The backend appears to have a blacklist filter. It blocks characters like `;`, `|`, and `\n`.

Analyzing the C source code I found an interesting flag in the `parse_opts` function of `leetspeak.c`:
```c
if (strcmp(argv[i], "-e") == 0) {
    exec_mode = 1;
    if (i+1 < argc) {
        ++i;
        command = malloc(strlen(argv[i])*sizeof(char));
        strcpy(command,argv[i]);
    }
}
```

If the `-e` option is passed, the program calls `executeCommand(command)`, which uses `execvp` to run `sh -c [command]`. This looks like an **Argument Injection** vulnerability. If I can pass `-e` through the web `options` parameter, I can execute system commands.

#### 2. Solution Strategy
To begin with I tried to trigger the RCE with `options=-e ls`. The server succesfully executes the command and returns its output, encoded in leatspeak:
![Pasted image 20260207061913.png](../_img/Pasted%20image%2020260207061913.png)

I notice the line `d3fini7ely_n07_7h3_fl4g.7x7`, refering to a file called `definitely_not_the_flag.txt` which looks that is definitely the flag.

I try to read its content with the same method using `more`, but since this command has more than one word it didn't work as expected. I got a timeout error that revealed the internal command structure: 

>[!error]
```error
Command '['/usr/bin/env', 'sh', '-c', 'echo test | ./leet -e more definitely_not_the_flag.txt | cat']' timed out`
```

This told me two things:
1. The Python wrapper uses a shell to pipe data.
2. If I use spaces in my `options`, Python’s `.split()` method breaks my command into separate arguments, and the C binary only takes the first word after `-e`.

#### 3. Execution and Flag
By wrapping the command in quotes, we force the shell to treat everything inside as a single argument for the `-e` flag.

We send the POST request again with the command inside quotes, and this time no error occurs, but we run into another problem:

_Payload:_
```
payload=test&options=-e "more definitely_not_the_flag.txt"
```

The word **"flag"** is present in a blacklist:  
![Pasted image 20260207063232.png](../_img/Pasted%20image%2020260207063232.png)

To bypass this blacklist, we use a wildcard `*`, avoiding writing the word "flag" in the command. The payload finally sent in the POST request is:

```
payload=test&options=-e "cat definitely*"
```

This time we successfully read the contents of the file, but once again, another problem appears. The server executed the command, read the file, and **translated the flag into leetspeak** before displaying it, returning the output `f5uC7F{wh9_h057_4ny7h1n6_0n_pr3m_wh3n_u_c0u1d_83_1337}`  

![Pasted image 20260207064926.png](../_img/Pasted%20image%2020260207064926.png)

We could try to reverse the translation by inspecting the transformations implemented in the C code. The problem is that the function responsible for the conversion (`convert2leet`) performs a destructive transformation, meaning it creates collisions that are impossible to resolve.

For example:

```c
switch (c) {
    case 'a': case 'A': input[i] = '4'; break;
    // ...
}
```

- If the original file contains an **'a'**, the program outputs **'4'**.
- If the original file contains a **'4'**, the program also outputs **'4'** (because '4' does not trigger any `switch` case and remains unchanged).

When we see a `4` in the output, it is mathematically impossible to know whether the original character was a letter or a number. Since the flag contained combinations of numbers interleaved with letters, manually translating the flag was not an option.

We need a way to extract the contents of the file without it passing through the character translation filter. We observe that the C code only alters alphabetic characters (`a, b, e, g, l, o, s, t`). **Numbers are not modified** by the `switch`.  
If we convert the contents of the file into a purely numeric representation before the binary processed it, the program would see numbers, ignore them, and return them intact.

> We chose **`od` (Octal Dump)**, a standard Linux tool used to dump files in different formats. We used the `-b` flag to obtain the octal representation byte by byte.

We built the payload to execute `od` instead of `cat`, keeping the quotes to protect the arguments:

```
payload=test&options=-e+"od+-b+definitely*"
```

After sending the payload, the server responded with a sequence of pure octal numbers:

![Pasted image 20260206074239.png](../_img/Pasted%20image%2020260206074239.png)

I convert the octal values to ASCII using an online tool to obtain the real text and got:

Flag: **`fsuCTF{wh9_h057_4ny7h1ng_0n_pr3m_wh3n_u_c0u1d_b3_1337}`**

---

### ==PROBLEM 4== - fat_cat
The challenge presents a web application that shows a cat GIF. The objective is to "feed" the cat an offering through a text input field. The application informs us that the cat requires a "massive offering to be satisfied." Upon submitting a standard string, the server redirects to a "Still Hungry" page, indicating that the input did not meet the required criteria.

#### 1. Analysis
I started by inspecting the provided source code for the application. The server uses the **Express** framework and defines three main routes: `/`, `/feed`, and `/still-hungry`.

The core logic resides in the `POST /feed` endpoint:
![Pasted image 20260207021636.png](../_img/Pasted%20image%2020260207021636.png)

The condition to obtain the flag is `food.length > 0xB16_C4A6A5`. I first converted the hexadecimal value to a decimal integer to understand the scale of the requirement:
$${0xB16\_C4A6A5=47,627,118,245}$$
This means the `food` variable must have a length of over **47 billion characters**.

I initially tried to send a standard POST request with a simple string to see the behavior:
![Pasted image 20260207015908.png](../_img/Pasted%20image%2020260207015908.png)

The result is a `HTTP 302 Redirect to /still-hungry` from the server.

>*Since the cat expects a string over 47 billion characters, sending a string big enough is not an option.*

#### 2. Solution Strategy
While reviewing the configuration, I noticed a specific line in the Express setup:

![Pasted image 20260207020759.png](../_img/Pasted%20image%2020260207020759.png)

I researched the difference between `extended: false` and `extended: true`.
- **`extended: false`**: Uses the classic `querystring` library
- **`extended: true`**: Uses the **`qs`** library

My research showed that the `qs` library allows for the creation of **nested objects** through the URI-encoded syntax. For example, a payload like `user[name]=admin` is parsed as `{ user: { name: 'admin' } }`.

In JavaScript, the `.length` property is commonly associated with strings and arrays. However, if I can control the input to be an **Object** instead of a **String**, I can manually define a property named `length`.

#### 3. Execution and Flag
To inject an object with a specific property using the `urlencoded` format, I used the square bracket notation: `food[length]=value`.

>I chose a value slightly larger than the requirement: **47,627,118,246**.

![Pasted image 20260207021822.png](../_img/Pasted%20image%2020260207021822.png)

The server processed the request. Because `extended` was set to `true`, `food` became the object `{ length: "47627118246" }`. When the `if` statement evaluated `food.length`, it retrieved my injected value. JavaScript then performed an implicit type conversion (casting the string to a number) to compare it with the hexadecimal constant.

The condition evaluated to `true`, and the server returned he flag:

![Pasted image 20260207021919.png](../_img/Pasted%20image%2020260207021919.png)


Flag:  `fsuCTF{1f_1_f17s_1_5i7s}`


