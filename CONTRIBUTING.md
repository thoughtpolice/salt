# Contributing

## Hacker notes

### Making changes to NaCl

**NOTE**: I will *NOT* accept any pull requests that make modifications to
the NaCl source, but do not add a note here. This is to sanely keep track
of what needs to be possibly kept up to date.

Likewise, if something here is no longer needed, then remove it.

  * Don't build CurveCP when doing a NaCl build
    Commit: 48d437af07442daf34408ceab7c513d37f2fc5f2
  * Add Ed25519 signature code from SUPERCOP.
    Commit: e9cc79508a1c6b9ec74e0dd9d3cbf625ccbd5148
  * Merge `randombytes.o` into `libnacl.a`.
    Commit: 58ff8f18e960ca537149efa88d86ca2ad7570578
  * Get rid of unused primitives in NaCl build, only including
    'preferred' interfaces. Removals include:

      * edwards25519sha512batch signature code
      * aes128ctr, salsa2012 and salsa208 streaming mode ciphers
      * hmacsha256 authentication.

    Commit: bf9cce5bb9f688c1a86a0f8db57e82d2b9235c90

  * Don't build tests or command line utilities.
    Commit: 6e7b919862ed14cbb6c257a73cf170df29161dcf
  * Remove amd64-optimized Ed25519 implementations 
    Commit: f9c4472506083d36343af8abbe858f0db8fc8662
