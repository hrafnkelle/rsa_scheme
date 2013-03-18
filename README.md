rsa_scheme
==========

Toy implementation of the RSA public key encryption in Guile Scheme.
I wrote this in 2001 as an academic excersise.
I put this up for historical reasons. 

Old README text
===============

Its currently possible to generate public/private key pairs, and
encrypt/decrypt messages in the form of numbers. 
I implemented it using Guile as my Scheme environment.
I think though it should be quite standard Scheme that should
run on any Scheme implementation. 

Its far from useable. The random number generation should
be done better (don't know about the underlying PRNG in Guile),
primality testing is currently done by making the number pass
one Miller-Rabin test (and that is not enough). Routines for handling
textstrings and textfiles need to be added etc.

I do not intend this for serious usage. I wrote this with two goals in
mind: 1) Learn Scheme
      2) Refresh my knowledge of RSA

Questions, comments and improvements are welcome!

Hrafnkell Eiriksson <he@klaki.net>
