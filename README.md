# Argon2


## Usage

`make` builds the executable `argon2`, the static library `libargon2.a`,
and the shared library `libargon2.so` (or on macOS, the dynamic library
`libargon2.dylib` -- make sure to specify the installation prefix when
you compile: `make PREFIX=/usr`). Make sure to run `make test` to verify
that your build produces valid results. `sudo make install PREFIX=/usr`
installs it to your system.



- disabled FLAG_clear_internal_memory;
- removed validation of parameters
- added gcc optimization
- 


## Intellectual property

Original repo:
https://github.com/P-H-C/phc-winner-argon2/

I kept the original LICENSE file in /orig_files/, as well as the IP statement.
