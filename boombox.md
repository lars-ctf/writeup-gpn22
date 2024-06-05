# Boombox

> Backback, rap crap, I got all the Flags 🚩 in my knapsack
## WIP
Boombox, is a crypto challenge. Given a rust program and its output, you have to find a way to decrypt the output. Let's examine the rust programm quick, I'm going to show you the entire code and afterward give you a brief description what's happening.

```rust
use rand::Rng;
use rand::rngs::ThreadRng;
use num::integer::gcd;
use num_bigint::BigUint;
use std::convert::TryInto;

fn rndint(rng: &mut ThreadRng, a: &BigUint, b: &BigUint) -> BigUint {
    let range = b - a + 1u32;
    let mut buf = vec![0u8; ((range.bits() + 7) / 8).try_into().unwrap()];
    loop {
        rng.fill(&mut buf[..]);
        let num = BigUint::from_bytes_be(&buf);
        if num < range {
            return a + num;
        }
    }
}

fn compose(n: usize, rng: &mut ThreadRng) -> ((Vec<BigUint>, BigUint, BigUint), Vec<BigUint>) {

    let two = BigUint::from(2u32);
    let ps: Vec<BigUint> = (0..n).map(|i| {
        let lower = (&two.pow(i as u32) - 1u32) * &two.pow(n as u32); 
        let upper = &two.pow(i as u32) * &two.pow(n as u32);
        rndint(rng, &lower, &upper) 
    }).collect();   

    let m_lower = &two.pow((2 * n + 1) as u32) + 1u32; 
    let m_upper = &two.pow((2 * n + 2) as u32) - 1u32; 
    let m = rndint(rng, &m_lower, &m_upper);           
   

    let tune = rndint(rng, &BigUint::from(2u32), &(m.clone() - 2u32));
    let t = &tune / gcd(tune.clone(), m.clone()); 


    let mictape: Vec<BigUint> = ps.iter().map(|a| (&t * a) % &m).collect();
    if gcd(t.clone(), m.clone()) != BigUint::from(1u32) {
        return compose(n, rng);
    }
    ((ps, t, m), mictape)
}

fn record(msg: &[bool], mic: &[BigUint]) -> BigUint {
    msg.iter().zip(mic).filter(|(&msg_bit, _)| msg_bit).map(|(_, mic_val)| mic_val.clone()).sum()
}

fn main() {
    let n: usize = 42;
    let mut rng = rand::thread_rng();
    let ((ps, t, m), mic) = compose(n, &mut rng);
    // stop thread
    println!("{:?}", mic);

    let msg_str = "GPNCTF{fake_flag}";
    let msg_bytes = msg_str.as_bytes();
    let msg_bin: Vec<bool> = msg_bytes.iter()
                                      .flat_map(|&byte| format!("{:08b}", byte)
                                      
                                      .chars()
                                      .map(|c| {println!("{}", c); c})
                                      .map(|c| c == '1').collect::<Vec<bool>>())
                                      .collect(); // 
    for chunk in msg_bin.chunks(n) { 
        let mut msg_chunk = chunk.to_vec(); 
        if msg_chunk.len() < n {
            msg_chunk.resize(n, false); // padding
        }
        let c = record(&msg_chunk, &mic);
        println!("{}", c);
        break;
    }
}
```
`rndint` just generates random numbers in the range from `a` to `b`, the used random number generator seems cryptographically secure.

`compose` generates a list of random numeric values, called `mictape` which is then returned alongside other values, yet only `mictape` is used. For now, I decided not to worry about the details of `compose`.

`record` takes two lists, one list `msg` consisting of bool values and one list `mic` containing numeric values. Then it zips the two lists and sums the value of `msg` when the zipped element of `mic` is true. The sum gets returned.

`main` first generates a random list `mic` with `compose`. Afterward, it decodes the Flag 🚩 into it's ASCII representation and then maps each bit to booleans, (bit=1 <=> true). Now the important part, it calls `record` with `mic` and the previously generated booleans (aka the Flag 🚩). Note that as `mic` contains only 42 values, we split the Flag 🚩 into chunks of equal size and calls `record` for each chunk. Then each chunk and `mic` gets printed. 

At this point, I was thinking, we just need to find the subset sum for each sum over `mic`. The indices of all summed elements in mic would then correspond to the bits of the Flag 🚩. Unfortunately, I also knew that subset sum is a NP-complete problem, so finding a solution for 42 possible summands isn't feasible. Yet, I decided to give it a quick shot and wrote a little python script to test my hypothesis. Unfortunately, my computer was not able to double time flow as fast as Eminem and to no one's surprise, no chunk was decrypted. 
So I needed to search for a different solution, and typed the words `subset sum crypto` into my search engine of choice, and the first result was [this lecture](https://web.eecs.umich.edu/~cpeikert/lic13/lec05.pdf). Quickly shimming over it, I found the words `Knapsack Cryptography`. Knowing that subset-sum is just a special case of the knapsack (another NP-complete problem), I typed the words `Knapsack Cryptography` into my search engine. This lead me to [this article](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem) about the Merkle–Hellman knapsack cryptosystem.
So I had a look how this cryptosystem works, and realized a striking similarity between the `compose` function and the section `Key generation`. In fact, if you take a closer look at it, you will see that `compose` just implements everything as described in the `Key generation` section. Furthermore, the `Encryption` section aligns with our `record` function. Nice 🎉! We found the used cipher, how cool would it be if there would be if there was a section called `Cryptanalysis` stating that it's rather easy to break the cipher. Oh, wait, there is! Unfortunately it's not really detailed, but after a bit of searching the i found [this great article](https://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf) on how to attack the Merkle–Hellman knapsack cryptosystem. If you want to gain a better understanding on how the attack works, I would highly recommend reading the article, if you just here for the top level solution stay with me. The main take away  is that we can construct a matrix of the form:
```
[I_42x42    0_42x1]
[Mic_1x42  -C_1x1 ]
(C is the sum of a chunk)
```
Then we can use the [LLL](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)-algorithm to find solutions for our subset-sum problem. Namely, a column consisting of only '1's and '0's with the last element being a zero is a valid solution, in that sense that the column directly corresponds to our bits of the chunk (excluding the last 0). This is the case because the collum is a solution to the subset sum problem, where '1' means the element in `mic` at the same index is part of the sum. Again, if you want to understand why this works and how this produces a solution for a seemingly NP-complete problem in poly-time, check out the previously mentioned [article](https://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf). 

Next, I wanted to write a python script to find solutions for each block, to my disappointment I couldn't get any library which implements LLL to work. This was about 1 hour before the deadline of the Flag 🚩 submission, so I searched for different options and found [this website](https://shrek.unideb.hu/~tengely/crypto/section-10.html) where you can just paste a list in the form of:
```
[mic, c]
```
and it calculates solutions for your input using LLL. And this worked great, apart from the fact, that I had to do this for every chunks by hand. Until I found out that for 2 of the 5 chunks, there was no solution. But after a bit, I realized that I can just change one value in `mic` to a rather large value, and hope the changed value isn't part of the subset-sum. And after a bit of trial and error, I had solutions for every block.
So I write a little program to encode the bits into letters (In rust of course):
```rust
use std::{num::ParseIntError};  
  
pub fn decode_binary(s: &str) -> Result<Vec<u8>, ParseIntError> {  
 (0..s.len())  
  .step_by(9)  
  .map(|i| u8::from_str_radix(&s[i..i + 8], 2))  
  .collect()  
}  
  
fn main() -> Result<(), ParseIntError> {  
  let binary: &str = "01000111 01010000 01001110 01000011 01010100 01000110 01111011 01100010 01100001 01100011 01101011 01110000 00110100 01100011 01101011 01011111 01110010 00110100 01110000 01011111 01100011 01110010 01100001 01110000 00101100 01011111 01111001 01100001 01110000 00101101 01111001 01100001 01110000 00101100 01011111 01111001 01100001 01100011 01101011 00110001 01110100 01111001 00101101 01111001 01100001 01100011 01101011 01111101";  
    println!("{:?}", String::from_utf8(decode_binary(binary)?));  
    Ok(())  
}
```
```
> cargo run
Ok("GPNCTF{backp4ck_r4p_crap,_yap-yap,_yack1ty-yack}")
```
And after submitting the Flag 🚩, a video of Eminem started playing, nice!
