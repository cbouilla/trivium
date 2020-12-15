/* 
 * PRNG-style implementation of trivium (64-bit version).
 * Author: Charles Bouillaguet (charles.bouillaguet@lip6.fr).
 *
 * This version operates on 64-bit words and returns 64 pseudo-random bits.
 *
 * Trivium is a stream cipher (cryptographic-strength RNG) selected by eSTREAM 
 * (part of the the EU ECRYPT project) to be part of a portfolio of secure 
 * algorithms (https://www.ecrypt.eu.org/stream/).
 *
 * Trivium has been designed by Christophe De Cannière and Bart Preneel.
 * This code generates the same output as trivium's reference implementation.
 *
 * The generator takes a 64-bit seed and a 64-bit "sequence number" (this allows
 * to generate independent sequences with the same seed).
 */
#include <inttypes.h>

uint64_t s11, s12, s21, s22, s31, s32;	/* global internal state */

uint64_t trivium64_next()
{
	uint64_t s66 = (s12 << 62) ^ (s11 >> 2);
	uint64_t s93 = (s12 << 35) ^ (s11 >> 29);
	uint64_t s162 = (s22 << 59) ^ (s21 >> 5);
	uint64_t s177 = (s22 << 44) ^ (s21 >> 20);
	uint64_t s243 = (s32 << 62) ^ (s31 >> 2);
	uint64_t s288 = (s32 << 17) ^ (s31 >> 47);
	uint64_t s91 = (s12 << 37) ^ (s11 >> 27);
	uint64_t s92 = (s12 << 36) ^ (s11 >> 28);
	uint64_t s171 = (s22 << 50) ^ (s21 >> 14);
	uint64_t s175 = (s22 << 46) ^ (s21 >> 18);
	uint64_t s176 = (s22 << 45) ^ (s21 >> 19);
	uint64_t s264 = (s32 << 41) ^ (s31 >> 23);
	uint64_t s286 = (s32 << 19) ^ (s31 >> 45);
	uint64_t s287 = (s32 << 18) ^ (s31 >> 46);
	uint64_t s69 = (s12 << 59) ^ (s11 >> 5);
	uint64_t t1 = s66 ^ s93;	/* update */
	uint64_t t2 = s162 ^ s177;
	uint64_t t3 = s243 ^ s288;
	uint64_t z = t1 ^ t2 ^ t3;
	t1 ^= (s91 & s92) ^ s171;
	t2 ^= (s175 & s176) ^ s264;
	t3 ^= (s286 & s287) ^ s69;
	s12 = s11;		/* rotate */
	s11 = t3;
	s22 = s21;
	s21 = t1;
	s32 = s31;
	s31 = t2;
	return z;
}

void trivium64_setseed(uint64_t seed, uint64_t seq)
{
	s11 = seed;
	s12 = 0;
	s21 = seq;
	s22 = 0;
	s31 = 0;
	s32 = 0x700000000000;
	for (int i = 0; i < 18; i++)	/* blank rounds */
		trivium64_next();
}
