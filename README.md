# Argon2 wordlist cracker

## Description

Modified the original Argon2 code to allow some simple password cracking.

Edit: Hashcat now has [argon1](https://hashcat.net/forum/thread-13330.html) support.


## Usage

```
./argon2 -w "/path/to/pwdlist" -e '$argon2id$v=19$m=4096,t=3,p=1$iurr6y6xk2X7X/YVOEQXBg$ti9/be9VgbXtJWpm1hoYyLm8V0wBGr+dxu9X+PFbpZI'
Password was: Hello World
```


## Done

Spent couple of days optimizing, went back to simple approach in the main file `src/run.c`:
- just a simple loop that uses argon2_verify()
- disabled FLAG_clear_internal_memory
- removed validation of parameters
- added gcc optimization


## Benchmark

- Using `time` and a counter I measured it to crack about `670 H/s` with `m=4096,t=3,p=1`.
- I've found it to be faster than the Python crackers. The fastest I could find was https://github.com/p0dalirius/Argon2Cracker/tree/main but it crashes when loading large wordlists, because it loads the entire wordlist into memory.
- I've spent a couple of days optimizing the source code, making it multi-threaded, only to find out that this simple naive approach is about as fast, even though it's constantly parsing the entire hash string. The speed bottleneck seems to be the way in which Argon2 fills the memory blocks. The cool hip multi-threaded optimized version that's not making it any faster can be found in the `optimized` branch.


## GPU cracking

This is a temporary solution until an efficient solution comes out that utilizes other resources like GPUs for optimized cracking. Interesting links:

- GPU cracking PoC: https://gitlab.com/omos/argon2-gpu
- Hashcat issue for implementing a GPU version: https://github.com/hashcat/hashcat/issues/1966


## Intellectual property

Original repo:
https://github.com/P-H-C/phc-winner-argon2/

I kept the original LICENSE file in /orig_files/, as well as the IP statement.
