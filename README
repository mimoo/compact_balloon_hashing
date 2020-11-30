# Compact Balloon Hashing

This is a simplified and compact (~100LOC) implementation of Balloon Hashing as a memory-hard password-based key derivation function. 
See https://crypto.stanford.edu/balloon/ for more details.

Balloon Hashing can in theory be used to hash passwords but I have not implemented this API.

For some reason the paper, and the [reference implementation](https://github.com/henrycg/balloon/), implement slightly different algorithms. So nothing should be compatible really.
Yet this code should provide a good base to understand balloon hashing.

There are two interfaces:

* one that accepts a hash function as callback, so that you can use balloon hashing with your own hash function implementation.
* one that uses SHAKE as hash function.

