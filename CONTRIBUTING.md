# Contributing

## Commits

Rules for contribution:

  * 80-character column maximum.
  * The first line of a commit message should be 73 columns max.
  * Try to make commits self contained. One thing at a time.
    If it's a branch, squash the commits together to make one.
  * Always run tests. If benchmarks regress, give OS information,
    and we'll discuss.

### Notes on sign-offs and attributions, etc.

When you commit, **please use -s to add a Signed-off-by line**. I manage
the `Signed-off-by` line much like Git itself: by adding it, you make clear
that the contributed code abides by the source code license. I'm pretty
much always going to want you to do this.

I normally merge commits manually and give the original author attribution
via `git commit --author`. I also sign-off on it, and add an `Acked-by` field
which basically states "this commit is not totally ludicrous."

Other fields may be added in the same vein for attribution or other purposes
(`Suggested-by`, `Reviewed-by`, etc.)

## Hacker notes

### Making changes to NaCl

**NOTE**: I will *NOT* accept any pull requests that make modifications to
the NaCl source, but do not add a note here. This is to sanely keep track
of what needs to be possibly kept up to date.

  * Don't build CurveCP when doing a NaCl build.

    **Commit**: thoughtpolice/salt@48d437af07442daf34408ceab7c513d37f2fc5f2

  * Add Ed25519 signature code from SUPERCOP.

    **Commit**: thoughtpolice/salt@e9cc79508a1c6b9ec74e0dd9d3cbf625ccbd5148

  * Merge `randombytes.o` into `libnacl.a`.

    **Commit**: thoughtpolice/salt@58ff8f18e960ca537149efa88d86ca2ad7570578

  * Get rid of unused primitives in NaCl build, only including
    'preferred' interfaces. Removals include:

      * edwards25519sha512batch signature code
      * aes128ctr, salsa2012 and salsa208 streaming mode ciphers
      * hmacsha256 authentication.

    **Commit**: thoughtpolice/salt@bf9cce5bb9f688c1a86a0f8db57e82d2b9235c90

  * Don't build tests or command line utilities.

    **Commit**: thoughtpolice/salt@6e7b919862ed14cbb6c257a73cf170df29161dcf

  * Remove amd64-optimized Ed25519 implementations 

    **Commit**: thoughtpolice/salt@f9c4472506083d36343af8abbe858f0db8fc8662

  * Cut down build time by building for only one architecture

    **Commit**: thoughtpolice/salt@0acb4f76b3dd05172433a23070eef8eac9f3e4c1
