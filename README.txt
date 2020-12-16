This repository contains two implementations of Trivium.

This code has been written by Charles Bouillaguet (charles.bouillaguet@lip6.fr).
It is in the public domain.

Trivium has been designed by Christophe De Cannière and Bart Preneel. It is a 
stream cipher (i.e. a cryptographic-strength RNG) selected by eSTREAM  (part of
the the EU ECRYPT project) to be part of a portfolio of secure  algorithms
(https://www.ecrypt.eu.org/stream/). 

More information about trivium is available at:

	https://www.ecrypt.eu.org/stream/e2-trivium.html

The two versions in this repository generate the same output as trivium's
reference implementation.

It should pass all statisticall tests.

The 32-bit version operates on 32-bit words and returns 32 pseudo-random bits.
The 64-bit version operates on 64-bit words and returns 64 pseudo-random bits.

The next output from the 64-bit version is the same as the next two outputs from
the 32-bit version. The 64-bit version run at >= 1GB/s on a recent laptop.

The generator takes a 64-bit seed and a 64-bit "sequence number" (this allows
to generate independent sequences with the same seed).