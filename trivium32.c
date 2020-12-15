/* 
 * PRNG-style implementation of trivium.
 * Author: Charles Bouillaguet (charles.bouillaguet@lip6.fr).
 *
 * This version operates on 32-bit words and returns 32 pseudo-random bits.
 *
 * Trivium is a stream cipher (cryptographic-strength RNG) selected by eSTREAM 
 * (part of the the EU ECRYPT project) to be part of a portfolio of secure 
 * algorithms (https://www.ecrypt.eu.org/stream/).
 *
 * Trivium has been designed by Christophe De Cannière and Bart Preneel.
 *
 * This code generates the same output as trivium's reference implementation.
 *
 * The generator takes a 64-bit seed and a 64-bit "sequence number" (this allows
 * to generate independent sequences with the same seed). */
#include <inttypes.h>

uint32_t s11, s12, s13, s21, s22, s23, s31, s32, s33, s34;	/* global internal state */

uint32_t trivium32_next()
{
	uint32_t s66 = (s13 << 30) ^ (s12 >> 2);
	uint32_t s93 = (s13 << 3) ^ (s12 >> 29);
	uint32_t s162 = (s23 << 27) ^ (s22 >> 5);
	uint32_t s177 = (s23 << 12) ^ (s22 >> 20);
	uint32_t s243 = (s33 << 30) ^ (s32 >> 2);
	uint32_t s288 = (s34 << 17) ^ (s33 >> 15);
	uint32_t s91 = (s13 << 5) ^ (s12 >> 27);
	uint32_t s92 = (s13 << 4) ^ (s12 >> 28);
	uint32_t s171 = (s23 << 18) ^ (s22 >> 14);
	uint32_t s175 = (s23 << 14) ^ (s22 >> 18);
	uint32_t s176 = (s23 << 13) ^ (s22 >> 19);
	uint32_t s264 = (s33 << 9) ^ (s32 >> 23);
	uint32_t s286 = (s34 << 19) ^ (s33 >> 13);
	uint32_t s287 = (s34 << 18) ^ (s33 >> 14);
	uint32_t s69 = (s13 << 27) ^ (s12 >> 5);
	uint32_t t1 = s66 ^ s93;	/* update */
	uint32_t t2 = s162 ^ s177;
	uint32_t t3 = s243 ^ s288;
	uint32_t z = t1 ^ t2 ^ t3;
	t1 ^= (s91 & s92) ^ s171;
	t2 ^= (s175 & s176) ^ s264;
	t3 ^= (s286 & s287) ^ s69;
	s13 = s12;		/* rotate */
	s12 = s11;
	s11 = t3;
	s23 = s22;
	s22 = s21;
	s21 = t1;
	s34 = s33;
	s33 = s32;
	s32 = s31;
	s31 = t2;
	return z;
}

void trivium32_setseed(uint64_t seed, uint64_t seq)
{
	s11 = seed;
	s12 = seed >> 32;
	s13 = 0;
	s21 = seq;
	s22 = seq >> 32;
	s23 = 0;
	s31 = 0;
	s32 = 0;
	s33 = 0;
	s34 = 0x7000;
	for (int i = 0; i < 36; i++)	/* blank rounds */
		trivium32_next();
}
