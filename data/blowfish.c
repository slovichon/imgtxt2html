/*	$OpenBSD$	*/

/*
 * Blowfish block cipher for OpenBSD
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Implementation advice by David Mazieres <dm@lcs.mit.edu>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code is derived from section 14.3 and the given source
 * in section V of Applied Cryptography, second edition.
 * Blowfish is an unpatented fast block cipher designed by
 * Bruce Schneier.
 */

#include <sys/param.h>
#include <sys/systm.h>

#include <crypto/blf.h>

#undef inline
#ifdef __GNUC__
#define inline __inline
#else				/* !__GNUC__ */
#define inline
#endif				/* !__GNUC__ */

/* Function for Feistel Networks */

#define F(s, x) ((((s)[        (((x)>>24)&0xFF)]  \
		 + (s)[0x100 + (((x)>>16)&0xFF)]) \
		 ^ (s)[0x200 + (((x)>> 8)&0xFF)]) \
		 + (s)[0x300 + ( (x)     &0xFF)])

#define BLFRND(s,p,i,j,n) (i ^= F(s,j) ^ (p)[n])

void
Blowfish_encipher(c, x)
	blf_ctx *c;
	u_int32_t *x;
{
	u_int32_t Xl;
	u_int32_t Xr;
	u_int32_t *s = c->S[0];
	u_int32_t *p = c->P;

	Xl = x[0];
	Xr = x[1];

	Xl ^= p[0];
	BLFRND(s, p, Xr, Xl, 1); BLFRND(s, p, Xl, Xr, 2);
	BLFRND(s, p, Xr, Xl, 3); BLFRND(s, p, Xl, Xr, 4);
	BLFRND(s, p, Xr, Xl, 5); BLFRND(s, p, Xl, Xr, 6);
	BLFRND(s, p, Xr, Xl, 7); BLFRND(s, p, Xl, Xr, 8);
	BLFRND(s, p, Xr, Xl, 9); BLFRND(s, p, Xl, Xr, 10);
	BLFRND(s, p, Xr, Xl, 11); BLFRND(s, p, Xl, Xr, 12);
	BLFRND(s, p, Xr, Xl, 13); BLFRND(s, p, Xl, Xr, 14);
	BLFRND(s, p, Xr, Xl, 15); BLFRND(s, p, Xl, Xr, 16);

	x[0] = Xr ^ p[17];
	x[1] = Xl;
}

void
Blowfish_decipher(c, x)
	blf_ctx *c;
	u_int32_t *x;
{
	u_int32_t Xl;
	u_int32_t Xr;
	u_int32_t *s = c->S[0];
	u_int32_t *p = c->P;

	Xl = x[0];
	Xr = x[1];

	Xl ^= p[17];
	BLFRND(s, p, Xr, Xl, 16); BLFRND(s, p, Xl, Xr, 15);
	BLFRND(s, p, Xr, Xl, 14); BLFRND(s, p, Xl, Xr, 13);
	BLFRND(s, p, Xr, Xl, 12); BLFRND(s, p, Xl, Xr, 11);
	BLFRND(s, p, Xr, Xl, 10); BLFRND(s, p, Xl, Xr, 9);
	BLFRND(s, p, Xr, Xl, 8); BLFRND(s, p, Xl, Xr, 7);
	BLFRND(s, p, Xr, Xl, 6); BLFRND(s, p, Xl, Xr, 5);
	BLFRND(s, p, Xr, Xl, 4); BLFRND(s, p, Xl, Xr, 3);
	BLFRND(s, p, Xr, Xl, 2); BLFRND(s, p, Xl, Xr, 1);

	x[0] = Xr ^ p[0];
	x[1] = Xl;
}

void
Blowfish_initstate(c)
	blf_ctx *c;
{

/* P-box and S-box tables initialized with digits of Pi */

	const blf_ctx initstate =

	{ {
		{
			0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
			0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
			0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
			0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
			0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
			0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
			0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
			0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
			0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
			0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
			0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
			0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
			0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
			0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
			0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
			0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
			0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
			0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
			0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
			0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
			0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
			0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
			0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
			0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
			0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
			0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
			0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
			0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
			0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
			0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
			0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
			0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
			0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
			0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
			0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
			0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
			0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
			0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
			0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
			0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
			0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
			0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
			0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
			0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
			0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
			0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
			0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
			0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
			0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
			0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
			0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
			0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
			0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
			0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
			0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
			0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
			0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
			0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
			0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
			0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
			0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
			0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
			0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
		0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a},
		{
			0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
			0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
			0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
			0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
			0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
			0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
			0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
			0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
			0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
			0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
			0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
			0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
			0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
			0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
			0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
			0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
			0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
			0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
			0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
			0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
			0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
			0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
			0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
			0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
			0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
			0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
			0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
			0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
			0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
			0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
			0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
			0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
			0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
			0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
			0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
			0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
			0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
			0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
			0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
			0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
			0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
			0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
			0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
			0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
			0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
			0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
			0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
			0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
			0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
			0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
			0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
			0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
			0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
			0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
			0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
			0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
			0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
			0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
			0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
			0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
			0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
			0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
			0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
		0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7},
		{
			0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
			0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
			0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
			0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
			0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
			0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
			0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
			0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
			0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
			0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
			0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
			0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
			0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
			0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
			0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
			0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
			0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
			0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
			0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
			0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
			0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
			0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
			0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
			0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
			0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
			0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
			0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
			0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
			0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
			0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
			0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
			0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
			0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
			0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
			0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
			0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
			0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
			0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
			0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
			0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
			0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
			0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
			0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
			0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
			0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
			0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
			0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
			0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
			0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
			0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
			0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
			0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
			0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
			0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
			0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
			0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
			0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
			0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
			0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
			0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
			0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
			0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
			0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
		0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0},
		{
			0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
			0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
			0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
			0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
			0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
			0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
			0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
			0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
			0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
			0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
			0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
			0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
			0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
			0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
			0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
			0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
			0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
			0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
			0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
			0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
			0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
			0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
			0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
			0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
			0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
			0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
			0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
			0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
			0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
			0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
			0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
			0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
			0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
			0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
			0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
			0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
			0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
			0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
			0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
			0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
			0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
			0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
			0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
			0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
			0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
			0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
			0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
			0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
			0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
			0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
			0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
			0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
			0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
			0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
			0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
			0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
			0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
			0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
			0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
			0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
			0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
			0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
			0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
		0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6}
	},
	{
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b
	} };

	*c = initstate;

}

#ifdef __STDC__
u_int32_t
Blowfish_stream2word(const u_int8_t *data, u_int16_t databytes, u_int16_t *current)
#else
u_int32_t
Blowfish_stream2word(data, databytes, current)
	const u_int8_t *data;
	u_int16_t databytes;
	u_int16_t *current;
#endif
{
	u_int8_t i;
	u_int16_t j;
	u_int32_t temp;

	temp = 0x00000000;
	j = *current;

	for (i = 0; i < 4; i++, j++) {
		if (j >= databytes)
			j = 0;
		temp = (temp << 8) | data[j];
	}

	*current = j;
	return temp;
}

#if __STDC__
void
Blowfish_expand0state(blf_ctx *c, const u_int8_t *key, u_int16_t keybytes)
#else
void
Blowfish_expand0state(c, key, keybytes)
	blf_ctx *c;
	const u_int8_t *key;
	u_int16_t keybytes;
#endif
{
	u_int16_t i;
	u_int16_t j;
	u_int16_t k;
	u_int32_t temp;
	u_int32_t data[2];

	j = 0;
	for (i = 0; i < BLF_N + 2; i++) {
		/* Extract 4 int8 to 1 int32 from keystream */
		temp = Blowfish_stream2word(key, keybytes, &j);
		c->P[i] = c->P[i] ^ temp;
	}

	j = 0;
	data[0] = 0x00000000;
	data[1] = 0x00000000;
	for (i = 0; i < BLF_N + 2; i += 2) {
		Blowfish_encipher(c, data);

		c->P[i] = data[0];
		c->P[i + 1] = data[1];
	}

	for (i = 0; i < 4; i++) {
		for (k = 0; k < 256; k += 2) {
			Blowfish_encipher(c, data);

			c->S[i][k] = data[0];
			c->S[i][k + 1] = data[1];
		}
	}
}


#if __STDC__
void
Blowfish_expandstate(blf_ctx *c, const u_int8_t *data, u_int16_t databytes,
		     const u_int8_t *key, u_int16_t keybytes)
#else
void
Blowfish_expandstate(c, data, databytes, key, keybytes)
	blf_ctx *c;
	const u_int8_t *data;
	u_int16_t databytes;
	const u_int8_t *key;
	u_int16_t keybytes;
#endif
{
	u_int16_t i;
	u_int16_t j;
	u_int16_t k;
	u_int32_t temp;
	u_int32_t d[2];

	j = 0;
	for (i = 0; i < BLF_N + 2; i++) {
		/* Extract 4 int8 to 1 int32 from keystream */
		temp = Blowfish_stream2word(key, keybytes, &j);
		c->P[i] = c->P[i] ^ temp;
	}

	j = 0;
	d[0] = 0x00000000;
	d[1] = 0x00000000;
	for (i = 0; i < BLF_N + 2; i += 2) {
		d[0] ^= Blowfish_stream2word(data, databytes, &j);
		d[1] ^= Blowfish_stream2word(data, databytes, &j);
		Blowfish_encipher(c, d);

		c->P[i] = d[0];
		c->P[i + 1] = d[1];
	}

	for (i = 0; i < 4; i++) {
		for (k = 0; k < 256; k += 2) {
			d[0]^= Blowfish_stream2word(data, databytes, &j);
			d[1] ^= Blowfish_stream2word(data, databytes, &j);
			Blowfish_encipher(c, d);

			c->S[i][k] = d[0];
			c->S[i][k + 1] = d[1];
		}
	}

}

#if __STDC__
void
blf_key(blf_ctx *c, const u_int8_t *k, u_int16_t len)
#else
void
blf_key(c, k, len)
	blf_ctx *c;
	const u_int8_t *k;
	u_int16_t len;
#endif
{
	/* Initalize S-boxes and subkeys with Pi */
	Blowfish_initstate(c);

	/* Transform S-boxes and subkeys with key */
	Blowfish_expand0state(c, k, len);
}

#if __STDC__
void
blf_enc(blf_ctx *c, u_int32_t *data, u_int16_t blocks)
#else
void
blf_enc(c, data, blocks)
	blf_ctx *c;
	u_int32_t *data;
	u_int16_t blocks;
#endif
{
	u_int32_t *d;
	u_int16_t i;

	d = data;
	for (i = 0; i < blocks; i++) {
		Blowfish_encipher(c, d);
		d += 2;
	}
}

#if __STDC__
void
blf_dec(blf_ctx *c, u_int32_t *data, u_int16_t blocks)
#else
void
blf_dec(c, data, blocks)
	blf_ctx *c;
	u_int32_t *data;
	u_int16_t blocks;
#endif
{
	u_int32_t *d;
	u_int16_t i;

	d = data;
	for (i = 0; i < blocks; i++) {
		Blowfish_decipher(c, d);
		d += 2;
	}
}

#if __STDC__
void
blf_ecb_encrypt(blf_ctx *c, u_int8_t *data, u_int32_t len)
#else
void
blf_ecb_encrypt(c, data, len)
     blf_ctx *c;
     u_int8_t *data;
     u_int32_t len;
#endif
{
	u_int32_t l, r, d[2];
	u_int32_t i;

	for (i = 0; i < len; i += 8) {
		l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
		r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
		d[0] = l;
		d[1] = r;
		Blowfish_encipher(c, d);
		l = d[0];
		r = d[1];
		data[0] = l >> 24 & 0xff;
		data[1] = l >> 16 & 0xff;
		data[2] = l >> 8 & 0xff;
		data[3] = l & 0xff;
		data[4] = r >> 24 & 0xff;
		data[5] = r >> 16 & 0xff;
		data[6] = r >> 8 & 0xff;
		data[7] = r & 0xff;
		data += 8;
	}
}

#if __STDC__
void
blf_ecb_decrypt(blf_ctx *c, u_int8_t *data, u_int32_t len)
#else
void
blf_ecb_decrypt(c, data, len)
     blf_ctx *c;
     u_int8_t *data;
     u_int32_t len;
#endif
{
	u_int32_t l, r, d[2];
	u_int32_t i;

	for (i = 0; i < len; i += 8) {
		l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
		r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
		d[0] = l;
		d[1] = r;
		Blowfish_decipher(c, d);
		l = d[0];
		r = d[1];
		data[0] = l >> 24 & 0xff;
		data[1] = l >> 16 & 0xff;
		data[2] = l >> 8 & 0xff;
		data[3] = l & 0xff;
		data[4] = r >> 24 & 0xff;
		data[5] = r >> 16 & 0xff;
		data[6] = r >> 8 & 0xff;
		data[7] = r & 0xff;
		data += 8;
	}
}

#if __STDC__
void
blf_cbc_encrypt(blf_ctx *c, u_int8_t *iv, u_int8_t *data, u_int32_t len)
#else
void
blf_cbc_encrypt(c, iv, data, len)
     blf_ctx *c;
     u_int8_t *iv;
     u_int8_t *data;
     u_int32_t len;
#endif
{
	u_int32_t l, r, d[2];
	u_int32_t i, j;

	for (i = 0; i < len; i += 8) {
		for (j = 0; j < 8; j++)
			data[j] ^= iv[j];
		l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
		r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
		d[0] = l;
		d[1] = r;
		Blowfish_encipher(c, d);
		l = d[0];
		r = d[1];
		data[0] = l >> 24 & 0xff;
		data[1] = l >> 16 & 0xff;
		data[2] = l >> 8 & 0xff;
		data[3] = l & 0xff;
		data[4] = r >> 24 & 0xff;
		data[5] = r >> 16 & 0xff;
		data[6] = r >> 8 & 0xff;
		data[7] = r & 0xff;
		iv = data;
		data += 8;
	}
}

#if __STDC__
void
blf_cbc_decrypt(blf_ctx *c, u_int8_t *iva, u_int8_t *data, u_int32_t len)
#else
void
blf_cbc_decrypt(c, iva, data, len)
     blf_ctx *c;
     u_int8_t *iva;
     u_int8_t *data;
     u_int32_t len;
#endif
{
	u_int32_t l, r, d[2];
	u_int8_t *iv;
	u_int32_t i, j;

	iv = data + len - 16;
	data = data + len - 8;
	for (i = len - 8; i >= 8; i -= 8) {
		l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
		r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
		d[0] = l;
		d[1] = r;
		Blowfish_decipher(c, d);
		l = d[0];
		r = d[1];
		data[0] = l >> 24 & 0xff;
		data[1] = l >> 16 & 0xff;
		data[2] = l >> 8 & 0xff;
		data[3] = l & 0xff;
		data[4] = r >> 24 & 0xff;
		data[5] = r >> 16 & 0xff;
		data[6] = r >> 8 & 0xff;
		data[7] = r & 0xff;
		for (j = 0; j < 8; j++)
			data[j] ^= iv[j];
		iv -= 8;
		data -= 8;
	}
	l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
	r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
	d[0] = l;
	d[1] = r;
	Blowfish_decipher(c, d);
	l = d[0];
	r = d[1];
	data[0] = l >> 24 & 0xff;
	data[1] = l >> 16 & 0xff;
	data[2] = l >> 8 & 0xff;
	data[3] = l & 0xff;
	data[4] = r >> 24 & 0xff;
	data[5] = r >> 16 & 0xff;
	data[6] = r >> 8 & 0xff;
	data[7] = r & 0xff;
	for (j = 0; j < 8; j++)
		data[j] ^= iva[j];
}
/*      $OpenBSD$       */

/*
 *	CAST-128 in C
 *	Written by Steve Reid <sreid@sea-to-sky.net>
 *	100% Public Domain - no warranty
 *	Released 1997.10.11
 */

#include <sys/types.h>
#include <crypto/cast.h>
#include <crypto/castsb.h>

/* Macros to access 8-bit bytes out of a 32-bit word */
#define U_INT8_Ta(x) ( (u_int8_t) (x>>24) )
#define U_INT8_Tb(x) ( (u_int8_t) ((x>>16)&255) )
#define U_INT8_Tc(x) ( (u_int8_t) ((x>>8)&255) )
#define U_INT8_Td(x) ( (u_int8_t) ((x)&255) )

/* Circular left shift */
#define ROL(x, n) ( ((x)<<(n)) | ((x)>>(32-(n))) )

/* CAST-128 uses three different round functions */
#define F1(l, r, i) \
	t = ROL(key->xkey[i] + r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U_INT8_Ta(t)] ^ cast_sbox2[U_INT8_Tb(t)]) - \
	 cast_sbox3[U_INT8_Tc(t)]) + cast_sbox4[U_INT8_Td(t)];
#define F2(l, r, i) \
	t = ROL(key->xkey[i] ^ r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U_INT8_Ta(t)] - cast_sbox2[U_INT8_Tb(t)]) + \
	 cast_sbox3[U_INT8_Tc(t)]) ^ cast_sbox4[U_INT8_Td(t)];
#define F3(l, r, i) \
	t = ROL(key->xkey[i] - r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U_INT8_Ta(t)] + cast_sbox2[U_INT8_Tb(t)]) ^ \
	 cast_sbox3[U_INT8_Tc(t)]) - cast_sbox4[U_INT8_Td(t)];


/***** Encryption Function *****/

void cast_encrypt(cast_key* key, u_int8_t* inblock, u_int8_t* outblock)
{
u_int32_t t, l, r;

	/* Get inblock into l,r */
	l = ((u_int32_t)inblock[0] << 24) | ((u_int32_t)inblock[1] << 16) |
	 ((u_int32_t)inblock[2] << 8) | (u_int32_t)inblock[3];
	r = ((u_int32_t)inblock[4] << 24) | ((u_int32_t)inblock[5] << 16) |
	 ((u_int32_t)inblock[6] << 8) | (u_int32_t)inblock[7];
	/* Do the work */
	F1(l, r,  0);
	F2(r, l,  1);
	F3(l, r,  2);
	F1(r, l,  3);
	F2(l, r,  4);
	F3(r, l,  5);
	F1(l, r,  6);
	F2(r, l,  7);
	F3(l, r,  8);
	F1(r, l,  9);
	F2(l, r, 10);
	F3(r, l, 11);
	/* Only do full 16 rounds if key length > 80 bits */
	if (key->rounds > 12) {
		F1(l, r, 12);
		F2(r, l, 13);
		F3(l, r, 14);
		F1(r, l, 15);
	}
	/* Put l,r into outblock */
	outblock[0] = U_INT8_Ta(r);
	outblock[1] = U_INT8_Tb(r);
	outblock[2] = U_INT8_Tc(r);
	outblock[3] = U_INT8_Td(r);
	outblock[4] = U_INT8_Ta(l);
	outblock[5] = U_INT8_Tb(l);
	outblock[6] = U_INT8_Tc(l);
	outblock[7] = U_INT8_Td(l);
	/* Wipe clean */
	t = l = r = 0;
}


/***** Decryption Function *****/

void cast_decrypt(cast_key* key, u_int8_t* inblock, u_int8_t* outblock)
{
u_int32_t t, l, r;

	/* Get inblock into l,r */
	r = ((u_int32_t)inblock[0] << 24) | ((u_int32_t)inblock[1] << 16) |
	 ((u_int32_t)inblock[2] << 8) | (u_int32_t)inblock[3];
	l = ((u_int32_t)inblock[4] << 24) | ((u_int32_t)inblock[5] << 16) |
	 ((u_int32_t)inblock[6] << 8) | (u_int32_t)inblock[7];
	/* Do the work */
	/* Only do full 16 rounds if key length > 80 bits */
	if (key->rounds > 12) {
		F1(r, l, 15);
		F3(l, r, 14);
		F2(r, l, 13);
		F1(l, r, 12);
	}
	F3(r, l, 11);
	F2(l, r, 10);
	F1(r, l,  9);
	F3(l, r,  8);
	F2(r, l,  7);
	F1(l, r,  6);
	F3(r, l,  5);
	F2(l, r,  4);
	F1(r, l,  3);
	F3(l, r,  2);
	F2(r, l,  1);
	F1(l, r,  0);
	/* Put l,r into outblock */
	outblock[0] = U_INT8_Ta(l);
	outblock[1] = U_INT8_Tb(l);
	outblock[2] = U_INT8_Tc(l);
	outblock[3] = U_INT8_Td(l);
	outblock[4] = U_INT8_Ta(r);
	outblock[5] = U_INT8_Tb(r);
	outblock[6] = U_INT8_Tc(r);
	outblock[7] = U_INT8_Td(r);
	/* Wipe clean */
	t = l = r = 0;
}


/***** Key Schedual *****/

void cast_setkey(cast_key* key, u_int8_t* rawkey, int keybytes)
{
u_int32_t t[4], z[4], x[4];
int i;

	/* Set number of rounds to 12 or 16, depending on key length */
	key->rounds = (keybytes <= 10 ? 12 : 16);

	/* Copy key to workspace x */
	for (i = 0; i < 4; i++) {
		x[i] = 0;
		if ((i*4+0) < keybytes) x[i] = (u_int32_t)rawkey[i*4+0] << 24;
		if ((i*4+1) < keybytes) x[i] |= (u_int32_t)rawkey[i*4+1] << 16;
		if ((i*4+2) < keybytes) x[i] |= (u_int32_t)rawkey[i*4+2] << 8;
		if ((i*4+3) < keybytes) x[i] |= (u_int32_t)rawkey[i*4+3];
	}
	/* Generate 32 subkeys, four at a time */
	for (i = 0; i < 32; i+=4) {
		switch (i & 4) {
		 case 0:
			t[0] = z[0] = x[0] ^ cast_sbox5[U_INT8_Tb(x[3])] ^
			 cast_sbox6[U_INT8_Td(x[3])] ^ cast_sbox7[U_INT8_Ta(x[3])] ^
			 cast_sbox8[U_INT8_Tc(x[3])] ^ cast_sbox7[U_INT8_Ta(x[2])];
			t[1] = z[1] = x[2] ^ cast_sbox5[U_INT8_Ta(z[0])] ^
			 cast_sbox6[U_INT8_Tc(z[0])] ^ cast_sbox7[U_INT8_Tb(z[0])] ^
			 cast_sbox8[U_INT8_Td(z[0])] ^ cast_sbox8[U_INT8_Tc(x[2])];
			t[2] = z[2] = x[3] ^ cast_sbox5[U_INT8_Td(z[1])] ^
			 cast_sbox6[U_INT8_Tc(z[1])] ^ cast_sbox7[U_INT8_Tb(z[1])] ^
			 cast_sbox8[U_INT8_Ta(z[1])] ^ cast_sbox5[U_INT8_Tb(x[2])];
			t[3] = z[3] = x[1] ^ cast_sbox5[U_INT8_Tc(z[2])] ^
			 cast_sbox6[U_INT8_Tb(z[2])] ^ cast_sbox7[U_INT8_Td(z[2])] ^
			 cast_sbox8[U_INT8_Ta(z[2])] ^ cast_sbox6[U_INT8_Td(x[2])];
			break;
		 case 4:
			t[0] = x[0] = z[2] ^ cast_sbox5[U_INT8_Tb(z[1])] ^
			 cast_sbox6[U_INT8_Td(z[1])] ^ cast_sbox7[U_INT8_Ta(z[1])] ^
			 cast_sbox8[U_INT8_Tc(z[1])] ^ cast_sbox7[U_INT8_Ta(z[0])];
			t[1] = x[1] = z[0] ^ cast_sbox5[U_INT8_Ta(x[0])] ^
			 cast_sbox6[U_INT8_Tc(x[0])] ^ cast_sbox7[U_INT8_Tb(x[0])] ^
			 cast_sbox8[U_INT8_Td(x[0])] ^ cast_sbox8[U_INT8_Tc(z[0])];
			t[2] = x[2] = z[1] ^ cast_sbox5[U_INT8_Td(x[1])] ^
			 cast_sbox6[U_INT8_Tc(x[1])] ^ cast_sbox7[U_INT8_Tb(x[1])] ^
			 cast_sbox8[U_INT8_Ta(x[1])] ^ cast_sbox5[U_INT8_Tb(z[0])];
			t[3] = x[3] = z[3] ^ cast_sbox5[U_INT8_Tc(x[2])] ^
			 cast_sbox6[U_INT8_Tb(x[2])] ^ cast_sbox7[U_INT8_Td(x[2])] ^
			 cast_sbox8[U_INT8_Ta(x[2])] ^ cast_sbox6[U_INT8_Td(z[0])];
			break;
		}
		switch (i & 12) {
		 case 0:
		 case 12:
			key->xkey[i+0] = cast_sbox5[U_INT8_Ta(t[2])] ^ cast_sbox6[U_INT8_Tb(t[2])] ^
			 cast_sbox7[U_INT8_Td(t[1])] ^ cast_sbox8[U_INT8_Tc(t[1])];
			key->xkey[i+1] = cast_sbox5[U_INT8_Tc(t[2])] ^ cast_sbox6[U_INT8_Td(t[2])] ^
			 cast_sbox7[U_INT8_Tb(t[1])] ^ cast_sbox8[U_INT8_Ta(t[1])];
			key->xkey[i+2] = cast_sbox5[U_INT8_Ta(t[3])] ^ cast_sbox6[U_INT8_Tb(t[3])] ^
			 cast_sbox7[U_INT8_Td(t[0])] ^ cast_sbox8[U_INT8_Tc(t[0])];
			key->xkey[i+3] = cast_sbox5[U_INT8_Tc(t[3])] ^ cast_sbox6[U_INT8_Td(t[3])] ^
			 cast_sbox7[U_INT8_Tb(t[0])] ^ cast_sbox8[U_INT8_Ta(t[0])];
			break;
		 case 4:
		 case 8:
			key->xkey[i+0] = cast_sbox5[U_INT8_Td(t[0])] ^ cast_sbox6[U_INT8_Tc(t[0])] ^
			 cast_sbox7[U_INT8_Ta(t[3])] ^ cast_sbox8[U_INT8_Tb(t[3])];
			key->xkey[i+1] = cast_sbox5[U_INT8_Tb(t[0])] ^ cast_sbox6[U_INT8_Ta(t[0])] ^
			 cast_sbox7[U_INT8_Tc(t[3])] ^ cast_sbox8[U_INT8_Td(t[3])];
			key->xkey[i+2] = cast_sbox5[U_INT8_Td(t[1])] ^ cast_sbox6[U_INT8_Tc(t[1])] ^
			 cast_sbox7[U_INT8_Ta(t[2])] ^ cast_sbox8[U_INT8_Tb(t[2])];
			key->xkey[i+3] = cast_sbox5[U_INT8_Tb(t[1])] ^ cast_sbox6[U_INT8_Ta(t[1])] ^
			 cast_sbox7[U_INT8_Tc(t[2])] ^ cast_sbox8[U_INT8_Td(t[2])];
			break;
		}
		switch (i & 12) {
		 case 0:
			key->xkey[i+0] ^= cast_sbox5[U_INT8_Tc(z[0])];
			key->xkey[i+1] ^= cast_sbox6[U_INT8_Tc(z[1])];
			key->xkey[i+2] ^= cast_sbox7[U_INT8_Tb(z[2])];
			key->xkey[i+3] ^= cast_sbox8[U_INT8_Ta(z[3])];
			break;
		 case 4:
			key->xkey[i+0] ^= cast_sbox5[U_INT8_Ta(x[2])];
			key->xkey[i+1] ^= cast_sbox6[U_INT8_Tb(x[3])];
			key->xkey[i+2] ^= cast_sbox7[U_INT8_Td(x[0])];
			key->xkey[i+3] ^= cast_sbox8[U_INT8_Td(x[1])];
			break;
		 case 8:
			key->xkey[i+0] ^= cast_sbox5[U_INT8_Tb(z[2])];
			key->xkey[i+1] ^= cast_sbox6[U_INT8_Ta(z[3])];
			key->xkey[i+2] ^= cast_sbox7[U_INT8_Tc(z[0])];
			key->xkey[i+3] ^= cast_sbox8[U_INT8_Tc(z[1])];
			break;
		 case 12:
			key->xkey[i+0] ^= cast_sbox5[U_INT8_Td(x[0])];
			key->xkey[i+1] ^= cast_sbox6[U_INT8_Td(x[1])];
			key->xkey[i+2] ^= cast_sbox7[U_INT8_Ta(x[2])];
			key->xkey[i+3] ^= cast_sbox8[U_INT8_Tb(x[3])];
			break;
		}
		if (i >= 16) {
			key->xkey[i+0] &= 31;
			key->xkey[i+1] &= 31;
			key->xkey[i+2] &= 31;
			key->xkey[i+3] &= 31;
		}
	}
	/* Wipe clean */
	for (i = 0; i < 4; i++) {
		t[i] = x[i] = z[i] = 0;
	}
}

/* Made in Canada */

/*	$OpenBSD$	*/

/*
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software. 
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/md5k.h>
#include <dev/rndvar.h>
#include <crypto/sha1.h>
#include <crypto/rmd160.h>
#include <crypto/cast.h>
#include <crypto/skipjack.h>
#include <crypto/blf.h>
#include <crypto/crypto.h>
#include <crypto/xform.h>

struct cryptocap *crypto_drivers = NULL;
int crypto_drivers_num = 0;

struct cryptop *cryptop_queue = NULL;
struct cryptodesc *cryptodesc_queue = NULL;

int crypto_queue_num = 0;
int crypto_queue_max = CRYPTO_MAX_CACHED;

struct cryptop *crp_req_queue = NULL;
struct cryptop **crp_req_queue_tail = NULL;

/*
 * Create a new session.
 */
int
crypto_newsession(u_int64_t *sid, struct cryptoini *cri)
{
    struct cryptoini *cr;
    u_int32_t hid, lid;
    int err;

    if (crypto_drivers == NULL)
      return EINVAL;

    /*
     * The algorithm we use here is pretty stupid; just use the
     * first driver that supports all the algorithms we need.
     *
     * XXX We need more smarts here (in real life too, but that's
     * XXX another story altogether).
     */

    for (hid = 0; hid < crypto_drivers_num; hid++)
    {
	/*
         * If it's not initialized or has remaining sessions referencing
         * it, skip.
         */
	if ((crypto_drivers[hid].cc_newsession == NULL) ||
	    (crypto_drivers[hid].cc_flags & CRYPTOCAP_F_CLEANUP))
	  continue;

	/* See if all the algorithms are supported */
	for (cr = cri; cr; cr = cr->cri_next)
	  if (crypto_drivers[hid].cc_alg[cr->cri_alg] == 0)
	    break;

	/* Ok, all algorithms are supported */
	if (cr == NULL)
	  break;
    }

    /*
     * Can't do everything in one session.
     *
     * XXX Fix this. We need to inject a "virtual" session layer right
     * XXX about here.
     */

    if (hid == crypto_drivers_num)
      return EINVAL;

    /* Call the driver initialization routine */
    lid = hid; /* Pass the driver ID */
    err = crypto_drivers[hid].cc_newsession(&lid, cri);
    if (err == 0)
    {
	(*sid) = hid;
	(*sid) <<= 32;
	(*sid) |= (lid & 0xffffffff);
        crypto_drivers[hid].cc_sessions++;
    }

    return err;
}

/*
 * Delete an existing session (or a reserved session on an unregistered
 * driver).
 */
int
crypto_freesession(u_int64_t sid)
{
    u_int32_t hid;
    int err = 0;

    if (crypto_drivers == NULL)
      return EINVAL;

    /* Determine two IDs */
    hid = (sid >> 32) & 0xffffffff;

    if (hid >= crypto_drivers_num)
      return ENOENT;

    if (crypto_drivers[hid].cc_sessions)
      crypto_drivers[hid].cc_sessions--;

    /* Call the driver cleanup routine, if available */
    if (crypto_drivers[hid].cc_freesession)
      err = crypto_drivers[hid].cc_freesession(sid);

    /*
     * If this was the last session of a driver marked as invalid, make
     * the entry available for reuse.
     */
    if ((crypto_drivers[hid].cc_flags & CRYPTOCAP_F_CLEANUP) &&
	(crypto_drivers[hid].cc_sessions == 0))
      bzero(&crypto_drivers[hid], sizeof(struct cryptocap));

    return err;
}

/*
 * Find an empty slot.
 */
int32_t
crypto_get_driverid(void)
{
    struct cryptocap *newdrv;
    int i;

    if (crypto_drivers_num == 0)
    {
	crypto_drivers_num = CRYPTO_DRIVERS_INITIAL;
	crypto_drivers = malloc(crypto_drivers_num * sizeof(struct cryptocap),
				M_XDATA, M_NOWAIT);
	if (crypto_drivers == NULL)
	{
	    crypto_drivers_num = 0;
	    return -1;
	}

	bzero(crypto_drivers, crypto_drivers_num * sizeof(struct cryptocap));
    }

    for (i = 0; i < crypto_drivers_num; i++)
      if ((crypto_drivers[i].cc_process == NULL) &&
	  !(crypto_drivers[i].cc_flags & CRYPTOCAP_F_CLEANUP) &&
	  (crypto_drivers[i].cc_sessions == 0))
	return i;

    /* Out of entries, allocate some more */
    if (i == crypto_drivers_num)
    {
	/* Be careful about wrap-around */
	if (2 * crypto_drivers_num <= crypto_drivers_num)
	  return -1;

	newdrv = malloc(2 * crypto_drivers_num * sizeof(struct cryptocap),
			M_XDATA, M_NOWAIT);
	if (newdrv == NULL)
	  return -1;

        bcopy(crypto_drivers, newdrv,
	      crypto_drivers_num * sizeof(struct cryptocap));
	bzero(&newdrv[crypto_drivers_num],
	      crypto_drivers_num * sizeof(struct cryptocap));
	crypto_drivers_num *= 2;
	return i;
    }

    /* Shouldn't really get here... */
    return -1;
}

/*
 * Register a crypto driver. It should be called once for each algorithm
 * supported by the driver.
 */
int
crypto_register(u_int32_t driverid, int alg,
    int (*newses)(u_int32_t *, struct cryptoini *),
    int (*freeses)(u_int64_t), int (*process)(struct cryptop *))
{
    if ((driverid >= crypto_drivers_num) || (alg <= 0) ||
	(alg > CRYPTO_ALGORITHM_MAX) || (crypto_drivers == NULL))
      return EINVAL;

    /*
     * XXX Do some performance testing to determine placing.
     * XXX We probably need an auxiliary data structure that describes
     * XXX relative performances.
     */

    crypto_drivers[driverid].cc_alg[alg] = 1;

    if (crypto_drivers[driverid].cc_process == NULL)
    {
	crypto_drivers[driverid].cc_newsession = newses;
	crypto_drivers[driverid].cc_process = process;
	crypto_drivers[driverid].cc_freesession = freeses;
    }

    return 0;
}

/*
 * Unregister a crypto driver. If there are pending sessions using it,
 * leave enough information around so that subsequent calls using those
 * sessions will correctly detect the driver being unregistered and reroute
 * the request.
 */
int
crypto_unregister(u_int32_t driverid, int alg)
{
    u_int32_t ses;
    int i;

    /* Sanity checks */
    if ((driverid >= crypto_drivers_num) || (alg <= 0) ||
        (alg > CRYPTO_ALGORITHM_MAX) || (crypto_drivers == NULL) ||
	(crypto_drivers[driverid].cc_alg[alg] == 0))
      return EINVAL;

    crypto_drivers[driverid].cc_alg[alg] = 0;

    /* Was this the last algorithm ? */
    for (i = 1; i <= CRYPTO_ALGORITHM_MAX; i++)
      if (crypto_drivers[driverid].cc_alg[i] != 0)
	break;

    if (i == CRYPTO_ALGORITHM_MAX + 1) 
    {
	ses = crypto_drivers[driverid].cc_sessions;
        bzero(&crypto_drivers[driverid], sizeof(struct cryptocap));

        if (ses != 0)
	{
            /* If there are pending sessions, just mark as invalid */
            crypto_drivers[driverid].cc_flags |= CRYPTOCAP_F_CLEANUP;
            crypto_drivers[driverid].cc_sessions = ses;
	}
    }

    return 0;
}

/*
 * Add crypto request to a queue, to be processed by a kernel thread.
 */
int
crypto_dispatch(struct cryptop *crp)
{
    int s = splhigh();

    if (crp_req_queue == NULL) {
	crp_req_queue = crp;
	crp_req_queue_tail = &(crp->crp_next);
	wakeup((caddr_t) &crp_req_queue);
    } else {
	*crp_req_queue_tail = crp;
	crp_req_queue_tail = &(crp->crp_next);
    }
    splx(s);
    return 0;
}

/*
 * Dispatch a crypto request to the appropriate crypto devices.
 */
int
crypto_invoke(struct cryptop *crp)
{
    struct cryptodesc *crd;
    u_int64_t nid;
    u_int32_t hid;

    /* Sanity checks */
    if ((crp == NULL) || (crp->crp_callback == NULL))
      return EINVAL;

    if ((crp->crp_desc == NULL) || (crypto_drivers == NULL))
    {
	crp->crp_etype = EINVAL;
	crypto_done(crp);
	return 0;
    }

    hid = (crp->crp_sid >> 32) & 0xffffffff;

    if (hid >= crypto_drivers_num)
    {
	/* Migrate session */
	for (crd = crp->crp_desc; crd->crd_next; crd = crd->crd_next)
	  crd->CRD_INI.cri_next = &(crd->crd_next->CRD_INI);

	if (crypto_newsession(&nid, &(crp->crp_desc->CRD_INI)) == 0)
	  crp->crp_sid = nid;

	crp->crp_etype = EAGAIN;
	crypto_done(crp);
	return 0;
    }

    if (crypto_drivers[hid].cc_flags & CRYPTOCAP_F_CLEANUP)
      crypto_freesession(crp->crp_sid);

    if (crypto_drivers[hid].cc_process == NULL)
    {
	/* Migrate session */
	for (crd = crp->crp_desc; crd->crd_next; crd = crd->crd_next)
	  crd->CRD_INI.cri_next = &(crd->crd_next->CRD_INI);

	if (crypto_newsession(&nid, &(crp->crp_desc->CRD_INI)) == 0)
	  crp->crp_sid = nid;

	crp->crp_etype = EAGAIN;
	crypto_done(crp);
	return 0;
    }

    crypto_drivers[hid].cc_process(crp);
    return 0;
}

/*
 * Release a set of crypto descriptors.
 */
void
crypto_freereq(struct cryptop *crp)
{
    struct cryptodesc *crd;
    int s;

    if (crp == NULL)
      return;

    s = splhigh();

    while ((crd = crp->crp_desc) != NULL)
    {
	crp->crp_desc = crd->crd_next;

	if (crypto_queue_num + 1 > crypto_queue_max)
	  FREE(crd, M_XDATA);
	else
	{
	    crd->crd_next = cryptodesc_queue;
	    cryptodesc_queue = crd;
	    crypto_queue_num++;
	}
    }

    if (crypto_queue_num + 1 > crypto_queue_max)
      FREE(crp, M_XDATA);
    else
    {
        crp->crp_next = cryptop_queue;
        cryptop_queue = crp;
        crypto_queue_num++;
    }

    splx(s);
}

/*
 * Acquire a set of crypto descriptors.
 */
struct cryptop *
crypto_getreq(int num)
{
    struct cryptodesc *crd;
    struct cryptop *crp;
    int s = splhigh();

    if (cryptop_queue == NULL)
    {
        MALLOC(crp, struct cryptop *, sizeof(struct cryptop), M_XDATA,
	       M_NOWAIT);
        if (crp == NULL)
        {
            splx(s);
            return NULL;
        }
    }
    else
    {
	crp = cryptop_queue;
	cryptop_queue = crp->crp_next;
        crypto_queue_num--;
    }

    bzero(crp, sizeof(struct cryptop));

    while (num--)
    {
        if (cryptodesc_queue == NULL)
	{
	    MALLOC(crd, struct cryptodesc *, sizeof(struct cryptodesc),
		   M_XDATA, M_NOWAIT);
	    if (crd == NULL)
	    {
                splx(s);
		crypto_freereq(crp);
	        return NULL;
	    }
	}
	else
	{
	    crd = cryptodesc_queue;
	    cryptodesc_queue = crd->crd_next;
	    crypto_queue_num--;
	}

	bzero(crd, sizeof(struct cryptodesc));
	crd->crd_next = crp->crp_desc;
	crp->crp_desc = crd;
    }

    splx(s);
    return crp;
}

/*
 * Crypto thread, runs as a kernel thread to process crypto requests.
 */
void
crypto_thread(void)
{
    struct cryptop *crp;
    int s;

    s = splhigh();

    for (;;)
    {
	crp = crp_req_queue;
	if (crp == NULL) /* No work to do */
	{
	    (void) tsleep(&crp_req_queue, PLOCK, "crypto_wait", 0);
	    continue;
	}

	/* Remove from the queue */
	crp_req_queue = crp->crp_next;
	splx(s);

	crypto_invoke(crp);

	s = splhigh();
    }
}

/*
 * Invoke the callback on behalf of the driver.
 */
void
crypto_done(struct cryptop *crp)
{
    crp->crp_callback(crp);
}
/* $OpenBSD$ */

/*
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software. 
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/md5k.h>
#include <dev/rndvar.h>
#include <crypto/sha1.h>
#include <crypto/rmd160.h>
#include <crypto/cast.h>
#include <crypto/skipjack.h>
#include <crypto/blf.h>
#include <crypto/crypto.h>
#include <crypto/cryptosoft.h>
#include <crypto/xform.h>

u_int8_t hmac_ipad_buffer[64] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };

u_int8_t hmac_opad_buffer[64] = {
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C };


struct swcr_data **swcr_sessions = NULL;
u_int32_t swcr_sesnum = 0;
int32_t swcr_id = -1;

/*
 * Apply a symmetric encryption/decryption algorithm.
 */
int
swcr_encdec(struct cryptodesc *crd, struct swcr_data *sw, caddr_t buf,
	    int outtype)
{
    unsigned char iv[EALG_MAX_BLOCK_LEN], blk[EALG_MAX_BLOCK_LEN], *idat;
    unsigned char *ivp, piv[EALG_MAX_BLOCK_LEN];
    struct enc_xform *exf;
    int i, k, j, blks;
    struct mbuf *m;

    exf = sw->sw_exf;
    blks = exf->blocksize;

    /* Check for non-padded data */
    if (crd->crd_len % blks)
      return EINVAL;

    if (outtype == CRYPTO_BUF_CONTIG)
    {
	if (crd->crd_flags & CRD_F_ENCRYPT)
	{
	    /* IV explicitly provided ? */
	    if (crd->crd_flags & CRD_F_IV_EXPLICIT)
	      bcopy(crd->crd_iv, sw->sw_iv, blks);

	    if (!(crd->crd_flags & CRD_F_IV_PRESENT))
	      bcopy(sw->sw_iv, buf + crd->crd_inject, blks);

	    for (i = crd->crd_skip;
		 i < crd->crd_skip + crd->crd_len;
		 i += blks)
	    {
		/* XOR with the IV/previous block, as appropriate. */
		if (i == crd->crd_skip)
		  for (k = 0; k < blks; k++)
		    buf[i + k] ^= sw->sw_iv[k];
		else
		  for (k = 0; k < blks; k++)
		    buf[i + k] ^= buf[i + k - blks];

		exf->encrypt(sw->sw_kschedule, buf + i);
	    }

	    /* Keep the last block */
	    bcopy(buf + crd->crd_len - blks, sw->sw_iv, blks);
	}
	else /* Decrypt */
	{
	    /* IV explicitly provided ? */
	    if (crd->crd_flags & CRD_F_IV_EXPLICIT)
	      bcopy(crd->crd_iv, sw->sw_iv, blks);
	    else /* IV preceeds data */
	      bcopy(buf + crd->crd_inject, sw->sw_iv, blks);

	    /*
	     * Start at the end, so we don't need to keep the encrypted
	     * block as the IV for the next block.
	     */
	    for (i = crd->crd_skip + crd->crd_len - blks;
		 i >= crd->crd_skip;
		 i -= blks)
	    {
		exf->decrypt(sw->sw_kschedule, buf + i);

		/* XOR with the IV/previous block, as appropriate */
		if (i == crd->crd_skip)
		  for (k = 0; k < blks; k++)
		    buf[i + k] ^= sw->sw_iv[k];
		else
		  for (k = 0; k < blks; k++)
		    buf[i + k] ^= buf[i + k - blks];
	    }
	}

	return 0; /* Done with contiguous buffer encryption/decryption */
    }
    else /* mbuf */
    {
	m = (struct mbuf *) buf;

	/* Initialize the IV */
	if (crd->crd_flags & CRD_F_ENCRYPT)
	{
	    /* IV explicitly provided ? */
	    if (crd->crd_flags & CRD_F_IV_EXPLICIT)
	      bcopy(crd->crd_iv, iv, blks);
	    else
	      bcopy(sw->sw_iv, iv, blks); /* Use IV from context */

	    /* Do we need to write the IV */
	    if (!(crd->crd_flags & CRD_F_IV_PRESENT))
	      m_copyback(m, crd->crd_inject, blks, iv);
	}
	else /* Decryption */
	{
	    /* IV explicitly provided ? */
	    if (crd->crd_flags & CRD_F_IV_EXPLICIT)
	      bcopy(crd->crd_iv, iv, blks);
	    else
	      m_copydata(m, crd->crd_inject, blks, iv); /* Get IV off mbuf */
	}

	ivp = iv;

	/* Find beginning of data */
	m = m_getptr(m, crd->crd_skip, &k);
	if (m == NULL)
	  return EINVAL;

	i = crd->crd_len;

	while (i > 0)
	{
	    /*
	     * If there's insufficient data at the end of an mbuf, we have
	     * to do some copying.
	     */
	    if ((m->m_len < k + blks) && (m->m_len != k))
	    {
		m_copydata(m, k, blks, blk);

		/* Actual encryption/decryption */
		if (crd->crd_flags & CRD_F_ENCRYPT)
		{
		    /* XOR with previous block */
		    for (j = 0; j < blks; j++)
		      blk[j] ^= ivp[j];

		    exf->encrypt(sw->sw_kschedule, blk);

		    /* Keep encrypted block for XOR'ing with next block */
		    bcopy(blk, iv, blks);
		    ivp = iv;
		}
		else /* decrypt */
		{
		    /* Keep encrypted block for XOR'ing with next block */
		    if (ivp == iv)
		      bcopy(blk, piv, blks);
		    else
		      bcopy(blk, iv, blks);

		    exf->decrypt(sw->sw_kschedule, blk);

		    /* XOR with previous block */
		    for (j = 0; j < blks; j++)
		      blk[j] ^= ivp[j];

		    if (ivp == iv)
		      bcopy(piv, iv, blks);
		    else
		      ivp = iv;
		}

		/* Copy back decrypted block */
		m_copyback(m, k, blks, blk);

		/* Advance pointer */
		m = m_getptr(m, k + blks, &k);
		if (m == NULL)
		  return EINVAL;

		i -= blks;

		/* Could be done... */
		if (i == 0)
		  break;
	    }

	    /* Skip possibly empty mbufs */
	    if (k == m->m_len)
	    {
		for (m = m->m_next; m && m->m_len == 0; m = m->m_next)
		  ;

		k = 0;
	    }

	    /* Sanity check */
	    if (m == NULL)
	      return EINVAL;

	    /*
	     * Warning: idat may point to garbage here, but we only use it
	     * in the while() loop, only if there are indeed enough data.
	     */
	    idat = mtod(m, unsigned char *) + k;

	    while ((m->m_len >= k + blks) && (i > 0))
	    {
		if (crd->crd_flags & CRD_F_ENCRYPT)
		{
		    /* XOR with previous block/IV */
		    for (j = 0; j < blks; j++)
		      idat[j] ^= ivp[j];

		    exf->encrypt(sw->sw_kschedule, idat);
		    ivp = idat;
		}
		else /* decrypt */
		{
		    /*
		     * Keep encrypted block to be used in next block's
		     * processing.
		     */
		    if (ivp == iv)
		      bcopy(idat, piv, blks);
		    else
		      bcopy(idat, iv, blks);

		    exf->decrypt(sw->sw_kschedule, idat);

		    /* XOR with previous block/IV */
		    for (j = 0; j < blks; j++)
		      idat[j] ^= ivp[j];

		    if (ivp == iv)
		      bcopy(piv, iv, blks);
		    else
		      ivp = iv;
		}

		idat += blks;
		k += blks;
		i -= blks;
	    }
	}

	/* Keep the last block */
	if (crd->crd_flags & CRD_F_ENCRYPT)
	  bcopy(ivp, sw->sw_iv, blks);

	return 0; /* Done with mbuf encryption/decryption */
    }

    /* Unreachable */
    return EINVAL;
}

/*
 * Compute keyed-hash authenticator.
 */
int
swcr_authcompute(struct cryptodesc *crd, struct swcr_data *sw,
		 caddr_t buf, int outtype)
{
    unsigned char aalg[AALG_MAX_RESULT_LEN];
    struct auth_hash *axf;
    union authctx ctx;
    int err;

    if (sw->sw_ictx == 0)
      return EINVAL;

    axf = sw->sw_axf;

    bcopy(sw->sw_ictx, &ctx, axf->ctxsize);

    if (outtype == CRYPTO_BUF_CONTIG)
      axf->Update(&ctx, buf + crd->crd_skip, crd->crd_len);
    else
    {
	err = m_apply((struct mbuf *) buf, crd->crd_skip,
		      crd->crd_len,
		      (int (*)(caddr_t, caddr_t, unsigned int)) axf->Update,
		      (caddr_t) &ctx);
	if (err)
	  return err;
    }

    switch (sw->sw_alg)
    {
	case CRYPTO_MD5_HMAC:
	case CRYPTO_SHA1_HMAC:
	case CRYPTO_RIPEMD160_HMAC:
	    if (sw->sw_octx == NULL)
	      return EINVAL;

            axf->Final(aalg, &ctx);
	    bcopy(sw->sw_octx, &ctx, axf->ctxsize);
	    axf->Update(&ctx, aalg, axf->hashsize);
	    axf->Final(aalg, &ctx);
	    break;

        case CRYPTO_MD5_KPDK:
        case CRYPTO_SHA1_KPDK:
	    if (sw->sw_octx == NULL)
	      return EINVAL;

	    axf->Update(&ctx, sw->sw_octx, sw->sw_klen);
	    axf->Final(aalg, &ctx);
            break;
    }

    /* Inject the authentication data */
    if (outtype == CRYPTO_BUF_CONTIG)
      bcopy(aalg, buf + crd->crd_inject, axf->authsize);
    else
      m_copyback((struct mbuf *) buf, crd->crd_inject, axf->authsize, aalg);

    return 0;
}

/*
 * Generate a new software session.
 */
int
swcr_newsession(u_int32_t *sid, struct cryptoini *cri)
{
    struct swcr_data **swd;
    struct auth_hash *axf;
    struct enc_xform *txf;
    u_int32_t i;
    int k;

    if ((sid == NULL) || (cri == NULL))
      return EINVAL;

    if (swcr_sessions)
      for (i = 1; i < swcr_sesnum; i++)
	if (swcr_sessions[i] == NULL)
	  break;

    if ((swcr_sessions == NULL) || (i == swcr_sesnum))
    {
	if (swcr_sessions == NULL)
	{
	    i = 1; /* We leave swcr_sessions[0] empty */
	    swcr_sesnum = CRYPTO_SW_SESSIONS;
	}
	else
	  swcr_sesnum *= 2;

	swd = malloc(swcr_sesnum * sizeof(struct swcr_data *),
		     M_XDATA, M_NOWAIT);
	if (swd == NULL)
	{
	    /* Reset session number */
	    if (swcr_sesnum == CRYPTO_SW_SESSIONS)
	      swcr_sesnum = 0;
	    else
	      swcr_sesnum /= 2;

	    return ENOBUFS;
	}

	bzero(swd, swcr_sesnum * sizeof(struct swcr_data *));

	/* Copy existing sessions */
	if (swcr_sessions)
	{
	    bcopy(swcr_sessions, swd,
		  (swcr_sesnum / 2) * sizeof(struct swcr_data *));
	    free(swcr_sessions, M_XDATA);
	}

	swcr_sessions = swd;
    }

    swd = &swcr_sessions[i];
    *sid = i;

    while (cri)
    {
	MALLOC(*swd, struct swcr_data *, sizeof(struct swcr_data), M_XDATA,
	       M_NOWAIT);
	if (*swd == NULL)
	{
	    swcr_freesession(i);
	    return ENOBUFS;
	}

	bzero(*swd, sizeof(struct swcr_data));

	switch (cri->cri_alg)
	{
	    case CRYPTO_DES_CBC:
		txf = &enc_xform_des;
		goto enccommon;

	    case CRYPTO_3DES_CBC:
		txf = &enc_xform_3des;
		goto enccommon;

	    case CRYPTO_BLF_CBC:
		txf = &enc_xform_blf;
		goto enccommon;

	    case CRYPTO_CAST_CBC:
		txf = &enc_xform_cast5;
		goto enccommon;

	    case CRYPTO_SKIPJACK_CBC:
		txf = &enc_xform_skipjack;
                goto enccommon;

	    case CRYPTO_RIJNDAEL128_CBC:
                txf = &enc_xform_rijndael128;
                goto enccommon;

	enccommon:
		txf->setkey(&((*swd)->sw_kschedule), cri->cri_key,
			    cri->cri_klen / 8);
		(*swd)->sw_iv = malloc(txf->blocksize, M_XDATA, M_NOWAIT);
		if ((*swd)->sw_iv == NULL)
		{
		    swcr_freesession(i);
		    return ENOBUFS;
		}

		(*swd)->sw_exf = txf;

		get_random_bytes((*swd)->sw_iv, txf->blocksize);
		break;

	    case CRYPTO_MD5_HMAC:
		axf = &auth_hash_hmac_md5_96;
		goto authcommon;

	    case CRYPTO_SHA1_HMAC:
		axf = &auth_hash_hmac_sha1_96;
		goto authcommon;
		
	    case CRYPTO_RIPEMD160_HMAC:
		axf = &auth_hash_hmac_ripemd_160_96;

	authcommon:
		(*swd)->sw_ictx = malloc(axf->ctxsize, M_XDATA, M_NOWAIT);
		if ((*swd)->sw_ictx == NULL)
		{
		    swcr_freesession(i);
		    return ENOBUFS;
		}

		(*swd)->sw_octx = malloc(axf->ctxsize, M_XDATA, M_NOWAIT);
		if ((*swd)->sw_octx == NULL)
		{
		    swcr_freesession(i);
		    return ENOBUFS;
		}

		for (k = 0; k < cri->cri_klen / 8; k++)
		  cri->cri_key[k] ^= HMAC_IPAD_VAL;

		axf->Init((*swd)->sw_ictx);
		axf->Update((*swd)->sw_ictx, cri->cri_key,
			    cri->cri_klen / 8);
		axf->Update((*swd)->sw_ictx, hmac_ipad_buffer,
			    HMAC_BLOCK_LEN - (cri->cri_klen / 8));

		for (k = 0; k < cri->cri_klen / 8; k++)
		  cri->cri_key[k] ^= (HMAC_IPAD_VAL ^ HMAC_OPAD_VAL);

		axf->Init((*swd)->sw_octx);
		axf->Update((*swd)->sw_octx, cri->cri_key,
			    cri->cri_klen / 8);
		axf->Update((*swd)->sw_octx, hmac_opad_buffer,
			    HMAC_BLOCK_LEN - (cri->cri_klen / 8));

		for (k = 0; k < cri->cri_klen / 8; k++)
		  cri->cri_key[k] ^= HMAC_OPAD_VAL;

		(*swd)->sw_axf = axf;
		break;

	    case CRYPTO_MD5_KPDK:
		axf = &auth_hash_key_md5;
		goto auth2common;

	    case CRYPTO_SHA1_KPDK:
		axf = &auth_hash_key_sha1;

	auth2common:
		(*swd)->sw_ictx = malloc(axf->ctxsize, M_XDATA, M_NOWAIT);
		if ((*swd)->sw_ictx == NULL)
		{
		    swcr_freesession(i);
		    return ENOBUFS;
		}

		/* Store the key so we can "append" it to the payload */
		(*swd)->sw_octx = malloc(cri->cri_klen / 8, M_XDATA, M_NOWAIT);
		if ((*swd)->sw_octx == NULL)
		{
		    swcr_freesession(i);
		    return ENOBUFS;
		}

		(*swd)->sw_klen = cri->cri_klen / 8;
		bcopy(cri->cri_key, (*swd)->sw_octx, cri->cri_klen / 8);

		axf->Init((*swd)->sw_ictx);
		axf->Update((*swd)->sw_ictx, cri->cri_key,
			    cri->cri_klen / 8);
		axf->Final(NULL, (*swd)->sw_ictx);

		(*swd)->sw_axf = axf;
		break;

	    default:
		swcr_freesession(i);
		return EINVAL;
	}

	(*swd)->sw_alg = cri->cri_alg;
	cri = cri->cri_next;
	swd = &((*swd)->sw_next);
    }

    return 0;
}

/*
 * Free a session.
 */
int
swcr_freesession(u_int64_t tid)
{
    struct swcr_data *swd;
    struct enc_xform *txf;
    struct auth_hash *axf;
    u_int32_t sid = ((u_int32_t) tid) & 0xffffffff;

    if ((sid > swcr_sesnum) || (swcr_sessions == NULL) ||
	(swcr_sessions[sid] == NULL))
      return EINVAL;

    /* Silently accept and return */
    if (sid == 0)
      return 0;

    while ((swd = swcr_sessions[sid]) != NULL)
    {
        swcr_sessions[sid] = swd->sw_next;

	switch (swd->sw_alg)
	{
	    case CRYPTO_DES_CBC:
	    case CRYPTO_3DES_CBC:
	    case CRYPTO_BLF_CBC:
	    case CRYPTO_CAST_CBC:
	    case CRYPTO_SKIPJACK_CBC:
	    case CRYPTO_RIJNDAEL128_CBC:
		txf = swd->sw_exf;

		if (swd->sw_kschedule)
		  txf->zerokey(&(swd->sw_kschedule));

		if (swd->sw_iv)
		  free(swd->sw_iv, M_XDATA);
		break;

	    case CRYPTO_MD5_HMAC:
	    case CRYPTO_SHA1_HMAC:
	    case CRYPTO_RIPEMD160_HMAC:
		axf = swd->sw_axf;

		if (swd->sw_ictx)
		{
		    bzero(swd->sw_ictx, axf->ctxsize);
		    free(swd->sw_ictx, M_XDATA);
		}

		if (swd->sw_octx)
		{
		    bzero(swd->sw_octx, axf->ctxsize);
		    free(swd->sw_octx, M_XDATA);
		}
		break;

	    case CRYPTO_MD5_KPDK:
	    case CRYPTO_SHA1_KPDK:
		axf = swd->sw_axf;

		if (swd->sw_ictx)
		{
		    bzero(swd->sw_ictx, axf->ctxsize);
		    free(swd->sw_ictx, M_XDATA);
		}

		if (swd->sw_octx)
		{
		    bzero(swd->sw_octx, swd->sw_klen);
		    free(swd->sw_octx, M_XDATA);
		}
		break;
	}

	FREE(swd, M_XDATA);
    }

    return 0;
}

/*
 * Process a software request.
 */
int
swcr_process(struct cryptop *crp)
{
    struct cryptodesc *crd;
    struct swcr_data *sw;
    u_int32_t lid;
    u_int64_t nid;
    int type;

    /* Sanity check */
    if (crp == NULL)
      return EINVAL;

    if ((crp->crp_desc == NULL) || (crp->crp_buf == NULL))
    {
	crp->crp_etype = EINVAL;
	goto done;
    }

    lid = crp->crp_sid & 0xffffffff;
    if ((lid >= swcr_sesnum) || (lid == 0) || (swcr_sessions[lid] == NULL))
    {
	crp->crp_etype = ENOENT;
	goto done;
    }

    if (crp->crp_flags & CRYPTO_F_IMBUF)
      type = CRYPTO_BUF_MBUF;
    else
      type = CRYPTO_BUF_CONTIG;

    /* Go through crypto descriptors, processing as we go */
    for (crd = crp->crp_desc; crd; crd = crd->crd_next)
    {
	/*
	 * Find the crypto context.
	 *
	 * XXX Note that the logic here prevents us from having
	 * XXX the same algorithm multiple times in a session
	 * XXX (or rather, we can but it won't give us the right
	 * XXX results). To do that, we'd need some way of differentiating
	 * XXX between the various instances of an algorithm (so we can
	 * XXX locate the correct crypto context).
	 */
	for (sw = swcr_sessions[lid];
	     sw && sw->sw_alg != crd->crd_alg;
	     sw = sw->sw_next)
	  ;

	/* No such context ? */
	if (sw == NULL)
	{
	    crp->crp_etype = EINVAL;
	    goto done;
	}

	switch (sw->sw_alg)
	{
	    case CRYPTO_DES_CBC:
	    case CRYPTO_3DES_CBC:
	    case CRYPTO_BLF_CBC:
	    case CRYPTO_CAST_CBC:
	    case CRYPTO_SKIPJACK_CBC:
	    case CRYPTO_RIJNDAEL128_CBC:
		if ((crp->crp_etype = swcr_encdec(crd, sw, crp->crp_buf,
						  type)) != 0)
		  goto done;
		break;

	    case CRYPTO_MD5_HMAC:
	    case CRYPTO_SHA1_HMAC:
	    case CRYPTO_RIPEMD160_HMAC:
	    case CRYPTO_MD5_KPDK:
	    case CRYPTO_SHA1_KPDK:
		if ((crp->crp_etype = swcr_authcompute(crd, sw, crp->crp_buf,
						       type)) != 0)
		  goto done;
		break;

	    default:  /* Unknown/unsupported algorithm */
		crp->crp_etype = EINVAL;
		goto done;
	}
    }

 done:
    if (crp->crp_etype == ENOENT)
    {
	crypto_freesession(crp->crp_sid); /* Just in case */

	/* Migrate session */
	for (crd = crp->crp_desc; crd->crd_next; crd = crd->crd_next)
	  crd->CRD_INI.cri_next = &(crd->crd_next->CRD_INI);

	if (crypto_newsession(&nid, &(crp->crp_desc->CRD_INI)) == 0)
	  crp->crp_sid = nid;
    }

    crypto_done(crp);
    return 0;
}

/*
 * Initialize the driver, called from the kernel main().
 */
void
swcr_init(void)
{
    swcr_id = crypto_get_driverid();
    if (swcr_id >= 0)
    {
	crypto_register(swcr_id, CRYPTO_DES_CBC, swcr_newsession,
                        swcr_freesession, swcr_process);
        crypto_register(swcr_id, CRYPTO_3DES_CBC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_BLF_CBC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_CAST_CBC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_SKIPJACK_CBC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_MD5_HMAC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_SHA1_HMAC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_RIPEMD160_HMAC, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_MD5_KPDK, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_SHA1_KPDK, NULL, NULL, NULL);
        crypto_register(swcr_id, CRYPTO_RIJNDAEL128_CBC, NULL, NULL, NULL);
	return;
    }

    /* This should never happen */
    panic("Software crypto device cannot initialize!");
}
/*	$OpenBSD$	*/

/* lib/des/ecb3_enc.c */
/* Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "des_locl.h"

void des_ecb3_encrypt(input, output, ks1, ks2, ks3, encrypt)
des_cblock (*input);
des_cblock (*output);
des_key_schedule ks1;
des_key_schedule ks2;
des_key_schedule ks3;
int encrypt;
	{
	register unsigned long l0,l1;
	register unsigned char *in,*out;
	unsigned long ll[2];

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	c2l(in,l0);
	c2l(in,l1);
	IP(l0,l1);
	ll[0]=l0;
	ll[1]=l1;
	des_encrypt2(ll,ks1,encrypt);
	des_encrypt2(ll,ks2,!encrypt);
	des_encrypt2(ll,ks3,encrypt);
	l0=ll[0];
	l1=ll[1];
	FP(l1,l0);
	l2c(l0,out);
	l2c(l1,out);
	}
/*	$OpenBSD$	*/

/* lib/des/ecb_enc.c */
/* Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "des_locl.h"
#include "spr.h"

const char *DES_version="libdes v 3.21 - 95/11/21 - eay";

void des_ecb_encrypt(input, output, ks, encrypt)
des_cblock (*input);
des_cblock (*output);
des_key_schedule ks;
int encrypt;
	{
	register unsigned long l0,l1;
	register unsigned char *in,*out;
	unsigned long ll[2];

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	c2l(in,l0); ll[0]=l0;
	c2l(in,l1); ll[1]=l1;
	des_encrypt(ll,ks,encrypt);
	l0=ll[0]; l2c(l0,out);
	l1=ll[1]; l2c(l1,out);
	l0=l1=ll[0]=ll[1]=0;
	}

void des_encrypt(data, ks, encrypt)
unsigned long *data;
des_key_schedule ks;
int encrypt;
	{
	register unsigned long l,r,t,u;
#ifdef DES_USE_PTR
	register unsigned char *des_SP=(unsigned char *)des_SPtrans;
#endif
#ifdef MSDOS
	union fudge {
		unsigned long  l;
		unsigned short s[2];
		unsigned char  c[4];
		} U,T;
#endif
	register int i;
	register unsigned long *s;

	u=data[0];
	r=data[1];

	IP(u,r);
	/* Things have been modified so that the initial rotate is
	 * done outside the loop.  This required the
	 * des_SPtrans values in sp.h to be rotated 1 bit to the right.
	 * One perl script later and things have a 5% speed up on a sparc2.
	 * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	 * for pointing this out. */
	l=(r<<1)|(r>>31);
	r=(u<<1)|(u>>31);

	/* clear the top bits on machines with 8byte longs */
	l&=0xffffffffL;
	r&=0xffffffffL;

	s=(unsigned long *)ks;
	/* I don't know if it is worth the effort of loop unrolling the
	 * inner loop */
	if (encrypt)
		{
		for (i=0; i<32; i+=4)
			{
			D_ENCRYPT(l,r,i+0); /*  1 */
			D_ENCRYPT(r,l,i+2); /*  2 */
			}
		}
	else
		{
		for (i=30; i>0; i-=4)
			{
			D_ENCRYPT(l,r,i-0); /* 16 */
			D_ENCRYPT(r,l,i-2); /* 15 */
			}
		}
	l=(l>>1)|(l<<31);
	r=(r>>1)|(r<<31);
	/* clear the top bits on machines with 8byte longs */
	l&=0xffffffffL;
	r&=0xffffffffL;

	FP(r,l);
	data[0]=l;
	data[1]=r;
	l=r=t=u=0;
	}

void des_encrypt2(data, ks, encrypt)
unsigned long *data;
des_key_schedule ks;
int encrypt;
	{
	register unsigned long l,r,t,u;
#ifdef DES_USE_PTR
	register unsigned char *des_SP=(unsigned char *)des_SPtrans;
#endif
#ifdef MSDOS
	union fudge {
		unsigned long  l;
		unsigned short s[2];
		unsigned char  c[4];
		} U,T;
#endif
	register int i;
	register unsigned long *s;

	u=data[0];
	r=data[1];

	/* Things have been modified so that the initial rotate is
	 * done outside the loop.  This required the
	 * des_SPtrans values in sp.h to be rotated 1 bit to the right.
	 * One perl script later and things have a 5% speed up on a sparc2.
	 * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	 * for pointing this out. */
	l=(r<<1)|(r>>31);
	r=(u<<1)|(u>>31);

	/* clear the top bits on machines with 8byte longs */
	l&=0xffffffffL;
	r&=0xffffffffL;

	s=(unsigned long *)ks;
	/* I don't know if it is worth the effort of loop unrolling the
	 * inner loop */
	if (encrypt)
		{
		for (i=0; i<32; i+=4)
			{
			D_ENCRYPT(l,r,i+0); /*  1 */
			D_ENCRYPT(r,l,i+2); /*  2 */
			}
		}
	else
		{
		for (i=30; i>0; i-=4)
			{
			D_ENCRYPT(l,r,i-0); /* 16 */
			D_ENCRYPT(r,l,i-2); /* 15 */
			}
		}
	l=(l>>1)|(l<<31);
	r=(r>>1)|(r<<31);
	/* clear the top bits on machines with 8byte longs */
	l&=0xffffffffL;
	r&=0xffffffffL;

	data[0]=l;
	data[1]=r;
	l=r=t=u=0;
	}
/*      $OpenBSD: mbuf.c,v 1.3 2000/04/24 04:54:19 deraadt Exp $	*/

/*
 * Copyright (c) 1999 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>

#include <crypto/crypto.h>

int
mbuf2pages(m, np, pp, lp, maxp, nicep)
	struct mbuf *m;
	int *np;
	long *pp;
	int *lp;
	int maxp;
	int *nicep;
{
	int npa = 0, tlen = 0;

	for (; m != NULL; m = m->m_next) {
		vaddr_t va, off;
		paddr_t pa;
		int len;

		if ((len = m->m_len) == 0)
			continue;
		tlen += len;
		va = (vaddr_t)m->m_data;
		off = va & PAGE_MASK;
		va -= off;

next_page:
		pa = pmap_extract(pmap_kernel(), va);
		if (pa == 0)
			panic("mbuf2pages: pa == 0");

		pa += off;

		lp[npa] = len;
		pp[npa] = pa;

		if (++npa > maxp)
			return (0);

		if (len + off > PAGE_SIZE) {
			lp[npa - 1] = PAGE_SIZE - off;
			va += PAGE_SIZE;
			len -= PAGE_SIZE;
			goto next_page;
		}
	}
			
	if (nicep) {
		int nice = 1;
		int i;

		/* see if each [pa,len] entry is long-word aligned */
		for (i = 0; i < npa; i++)
			if ((lp[i] & 3) || (pp[i] & 3))
				nice = 0;
		*nicep = nice;
	}

	*np = npa;
	return (tlen);
}
/*	$OpenBSD: rijndael.c,v 1.6 2000/12/09 18:51:34 markus Exp $	*/

/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         RIJNDAEL by Joan Daemen and Vincent Rijmen                   */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* Timing data for Rijndael (rijndael.c)

Algorithm: rijndael (rijndael.c)

128 bit key:
Key Setup:    305/1389 cycles (encrypt/decrypt)
Encrypt:       374 cycles =    68.4 mbits/sec
Decrypt:       352 cycles =    72.7 mbits/sec
Mean:          363 cycles =    70.5 mbits/sec

192 bit key:
Key Setup:    277/1595 cycles (encrypt/decrypt)
Encrypt:       439 cycles =    58.3 mbits/sec
Decrypt:       425 cycles =    60.2 mbits/sec
Mean:          432 cycles =    59.3 mbits/sec

256 bit key:
Key Setup:    374/1960 cycles (encrypt/decrypt)
Encrypt:       502 cycles =    51.0 mbits/sec
Decrypt:       498 cycles =    51.4 mbits/sec
Mean:          500 cycles =    51.2 mbits/sec

*/

#include <sys/param.h>
#include <sys/systm.h>

#include <crypto/rijndael.h>

void gen_tabs	__P((void));

/* 3. Basic macros for speeding up generic operations               */

/* Circular rotate of 32 bit values                                 */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

/* Invert byte order in a 32 bit variable                           */

#define bswap(x)    ((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00))

/* Extract byte from a 32 bit quantity (little endian notation)     */ 

#define byte(x,n)   ((u1byte)((x) >> (8 * n)))

#if BYTE_ORDER != LITTLE_ENDIAN
#define BYTE_SWAP
#endif

#ifdef  BYTE_SWAP
#define io_swap(x)  bswap(x)
#else
#define io_swap(x)  (x)
#endif

#define LARGE_TABLES

u1byte  pow_tab[256];
u1byte  log_tab[256];
u1byte  sbx_tab[256];
u1byte  isb_tab[256];
u4byte  rco_tab[ 10];
u4byte  ft_tab[4][256];
u4byte  it_tab[4][256];

#ifdef  LARGE_TABLES
  u4byte  fl_tab[4][256];
  u4byte  il_tab[4][256];
#endif

u4byte  tab_gen = 0;

#define ff_mult(a,b)    (a && b ? pow_tab[(log_tab[a] + log_tab[b]) % 255] : 0)

#define f_rn(bo, bi, n, k)                          \
    bo[n] =  ft_tab[0][byte(bi[n],0)] ^             \
             ft_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             ft_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             ft_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

#define i_rn(bo, bi, n, k)                          \
    bo[n] =  it_tab[0][byte(bi[n],0)] ^             \
             it_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             it_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             it_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#ifdef LARGE_TABLES

#define ls_box(x)                \
    ( fl_tab[0][byte(x, 0)] ^    \
      fl_tab[1][byte(x, 1)] ^    \
      fl_tab[2][byte(x, 2)] ^    \
      fl_tab[3][byte(x, 3)] )

#define f_rl(bo, bi, n, k)                          \
    bo[n] =  fl_tab[0][byte(bi[n],0)] ^             \
             fl_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             fl_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             fl_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

#define i_rl(bo, bi, n, k)                          \
    bo[n] =  il_tab[0][byte(bi[n],0)] ^             \
             il_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             il_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             il_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#else

#define ls_box(x)                            \
    ((u4byte)sbx_tab[byte(x, 0)] <<  0) ^    \
    ((u4byte)sbx_tab[byte(x, 1)] <<  8) ^    \
    ((u4byte)sbx_tab[byte(x, 2)] << 16) ^    \
    ((u4byte)sbx_tab[byte(x, 3)] << 24)

#define f_rl(bo, bi, n, k)                                      \
    bo[n] = (u4byte)sbx_tab[byte(bi[n],0)] ^                    \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 1) & 3],1)]),  8) ^  \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 3) & 3],3)]), 24) ^ *(k + n)

#define i_rl(bo, bi, n, k)                                      \
    bo[n] = (u4byte)isb_tab[byte(bi[n],0)] ^                    \
        rotl(((u4byte)isb_tab[byte(bi[(n + 3) & 3],1)]),  8) ^  \
        rotl(((u4byte)isb_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
        rotl(((u4byte)isb_tab[byte(bi[(n + 1) & 3],3)]), 24) ^ *(k + n)

#endif

void
gen_tabs(void)
{
	u4byte  i, t;
	u1byte  p, q;

	/* log and power tables for GF(2**8) finite field with  */
	/* 0x11b as modular polynomial - the simplest prmitive  */
	/* root is 0x11, used here to generate the tables       */

	for(i = 0,p = 1; i < 256; ++i) {
		pow_tab[i] = (u1byte)p; log_tab[p] = (u1byte)i;

		p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);
	}

	log_tab[1] = 0; p = 1;

	for(i = 0; i < 10; ++i) {
		rco_tab[i] = p; 

		p = (p << 1) ^ (p & 0x80 ? 0x1b : 0);
	}

	/* note that the affine byte transformation matrix in   */
	/* rijndael specification is in big endian format with  */
	/* bit 0 as the most significant bit. In the remainder  */
	/* of the specification the bits are numbered from the  */
	/* least significant end of a byte.                     */

	for(i = 0; i < 256; ++i) {
		p = (i ? pow_tab[255 - log_tab[i]] : 0); q = p; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q ^ 0x63; 
		sbx_tab[i] = (u1byte)p; isb_tab[p] = (u1byte)i;
	}

	for(i = 0; i < 256; ++i) {
		p = sbx_tab[i]; 

#ifdef  LARGE_TABLES        
        
		t = p; fl_tab[0][i] = t;
		fl_tab[1][i] = rotl(t,  8);
		fl_tab[2][i] = rotl(t, 16);
		fl_tab[3][i] = rotl(t, 24);
#endif
		t = ((u4byte)ff_mult(2, p)) |
			((u4byte)p <<  8) |
			((u4byte)p << 16) |
			((u4byte)ff_mult(3, p) << 24);
        
		ft_tab[0][i] = t;
		ft_tab[1][i] = rotl(t,  8);
		ft_tab[2][i] = rotl(t, 16);
		ft_tab[3][i] = rotl(t, 24);

		p = isb_tab[i]; 

#ifdef  LARGE_TABLES        
        
		t = p; il_tab[0][i] = t; 
		il_tab[1][i] = rotl(t,  8); 
		il_tab[2][i] = rotl(t, 16); 
		il_tab[3][i] = rotl(t, 24);
#endif 
		t = ((u4byte)ff_mult(14, p)) |
			((u4byte)ff_mult( 9, p) <<  8) |
			((u4byte)ff_mult(13, p) << 16) |
			((u4byte)ff_mult(11, p) << 24);
        
		it_tab[0][i] = t; 
		it_tab[1][i] = rotl(t,  8); 
		it_tab[2][i] = rotl(t, 16); 
		it_tab[3][i] = rotl(t, 24); 
	}

	tab_gen = 1;
}

#define star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)

#define imix_col(y,x)       \
    u   = star_x(x);        \
    v   = star_x(u);        \
    w   = star_x(v);        \
    t   = w ^ (x);          \
   (y)  = u ^ v ^ w;        \
   (y) ^= rotr(u ^ t,  8) ^ \
          rotr(v ^ t, 16) ^ \
          rotr(t,24)

/* initialise the key schedule from the user supplied key   */

#define loop4(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[4 * i];     e_key[4 * i + 4] = t;    \
    t ^= e_key[4 * i + 1]; e_key[4 * i + 5] = t;    \
    t ^= e_key[4 * i + 2]; e_key[4 * i + 6] = t;    \
    t ^= e_key[4 * i + 3]; e_key[4 * i + 7] = t;    \
}

#define loop6(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[6 * i];     e_key[6 * i + 6] = t;    \
    t ^= e_key[6 * i + 1]; e_key[6 * i + 7] = t;    \
    t ^= e_key[6 * i + 2]; e_key[6 * i + 8] = t;    \
    t ^= e_key[6 * i + 3]; e_key[6 * i + 9] = t;    \
    t ^= e_key[6 * i + 4]; e_key[6 * i + 10] = t;   \
    t ^= e_key[6 * i + 5]; e_key[6 * i + 11] = t;   \
}

#define loop8(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[8 * i];     e_key[8 * i + 8] = t;    \
    t ^= e_key[8 * i + 1]; e_key[8 * i + 9] = t;    \
    t ^= e_key[8 * i + 2]; e_key[8 * i + 10] = t;   \
    t ^= e_key[8 * i + 3]; e_key[8 * i + 11] = t;   \
    t  = e_key[8 * i + 4] ^ ls_box(t);              \
    e_key[8 * i + 12] = t;                          \
    t ^= e_key[8 * i + 5]; e_key[8 * i + 13] = t;   \
    t ^= e_key[8 * i + 6]; e_key[8 * i + 14] = t;   \
    t ^= e_key[8 * i + 7]; e_key[8 * i + 15] = t;   \
}

rijndael_ctx *
rijndael_set_key(rijndael_ctx *ctx, const u4byte *in_key, const u4byte key_len,
		 int encrypt)
{  
	u4byte  i, t, u, v, w;
	u4byte *e_key = ctx->e_key;
	u4byte *d_key = ctx->d_key;

	ctx->decrypt = !encrypt;

	if(!tab_gen)
		gen_tabs();

	ctx->k_len = (key_len + 31) / 32;

	e_key[0] = io_swap(in_key[0]); e_key[1] = io_swap(in_key[1]);
	e_key[2] = io_swap(in_key[2]); e_key[3] = io_swap(in_key[3]);
	
	switch(ctx->k_len) {
        case 4: t = e_key[3];
                for(i = 0; i < 10; ++i) 
			loop4(i);
                break;

        case 6: e_key[4] = io_swap(in_key[4]); t = e_key[5] = io_swap(in_key[5]);
                for(i = 0; i < 8; ++i) 
			loop6(i);
                break;

        case 8: e_key[4] = io_swap(in_key[4]); e_key[5] = io_swap(in_key[5]);
                e_key[6] = io_swap(in_key[6]); t = e_key[7] = io_swap(in_key[7]);
                for(i = 0; i < 7; ++i) 
			loop8(i);
                break;
	}

	if (!encrypt) {
		d_key[0] = e_key[0]; d_key[1] = e_key[1];
		d_key[2] = e_key[2]; d_key[3] = e_key[3];

		for(i = 4; i < 4 * ctx->k_len + 24; ++i) {
			imix_col(d_key[i], e_key[i]);
		}
	}

	return ctx;
}

/* encrypt a block of text  */

#define f_nround(bo, bi, k) \
    f_rn(bo, bi, 0, k);     \
    f_rn(bo, bi, 1, k);     \
    f_rn(bo, bi, 2, k);     \
    f_rn(bo, bi, 3, k);     \
    k += 4

#define f_lround(bo, bi, k) \
    f_rl(bo, bi, 0, k);     \
    f_rl(bo, bi, 1, k);     \
    f_rl(bo, bi, 2, k);     \
    f_rl(bo, bi, 3, k)

void
rijndael_encrypt(rijndael_ctx *ctx, const u4byte *in_blk, u4byte *out_blk)
{   
	u4byte k_len = ctx->k_len;
	u4byte *e_key = ctx->e_key;
	u4byte  b0[4], b1[4], *kp;

	b0[0] = io_swap(in_blk[0]) ^ e_key[0];
	b0[1] = io_swap(in_blk[1]) ^ e_key[1];
	b0[2] = io_swap(in_blk[2]) ^ e_key[2];
	b0[3] = io_swap(in_blk[3]) ^ e_key[3];

	kp = e_key + 4;

	if(k_len > 6) {
		f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	}

	if(k_len > 4) {
		f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	}

	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_lround(b0, b1, kp);

	out_blk[0] = io_swap(b0[0]); out_blk[1] = io_swap(b0[1]);
	out_blk[2] = io_swap(b0[2]); out_blk[3] = io_swap(b0[3]);
}

/* decrypt a block of text  */

#define i_nround(bo, bi, k) \
    i_rn(bo, bi, 0, k);     \
    i_rn(bo, bi, 1, k);     \
    i_rn(bo, bi, 2, k);     \
    i_rn(bo, bi, 3, k);     \
    k -= 4

#define i_lround(bo, bi, k) \
    i_rl(bo, bi, 0, k);     \
    i_rl(bo, bi, 1, k);     \
    i_rl(bo, bi, 2, k);     \
    i_rl(bo, bi, 3, k)

void
rijndael_decrypt(rijndael_ctx *ctx, const u4byte *in_blk, u4byte *out_blk)
{  
	u4byte  b0[4], b1[4], *kp;
	u4byte k_len = ctx->k_len;
	u4byte *e_key = ctx->e_key;
	u4byte *d_key = ctx->d_key;

	b0[0] = io_swap(in_blk[0]) ^ e_key[4 * k_len + 24];
	b0[1] = io_swap(in_blk[1]) ^ e_key[4 * k_len + 25];
	b0[2] = io_swap(in_blk[2]) ^ e_key[4 * k_len + 26];
	b0[3] = io_swap(in_blk[3]) ^ e_key[4 * k_len + 27];

	kp = d_key + 4 * (k_len + 5);

	if(k_len > 6) {
		i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	}

	if(k_len > 4) {
		i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	}

	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_lround(b0, b1, kp);

	out_blk[0] = io_swap(b0[0]); out_blk[1] = io_swap(b0[1]);
	out_blk[2] = io_swap(b0[2]); out_blk[3] = io_swap(b0[3]);
}
/*       $OpenBSD$       */

/********************************************************************\
 *
 *      FILE:     rmd160.c
 *
 *      CONTENTS: A sample C-implementation of the RIPEMD-160
 *		  hash-function.
 *      TARGET:   any computer with an ANSI C compiler
 *
 *      AUTHOR:   Antoon Bosselaers, ESAT-COSIC
 *		  (Arranged for libc by Todd C. Miller)
 *      DATE:     1 March 1996
 *      VERSION:  1.0
 *
 *      Copyright (c) Katholieke Universiteit Leuven
 *      1996, All Rights Reserved
 *
\********************************************************************/

/*  header files */
#include <sys/param.h>
#include <sys/systm.h>

#include <crypto/rmd160.h>

/********************************************************************/

/* macro definitions */

/* collect four bytes into one word: */
#define BYTES_TO_DWORD(strptr)			\
    (((u_int32_t) *((strptr)+3) << 24) |	\
    ((u_int32_t) *((strptr)+2) << 16) |		\
    ((u_int32_t) *((strptr)+1) <<  8) |		\
    ((u_int32_t) *(strptr)))

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n)	(((x) << (n)) | ((x) >> (32-(n))))

/* the three basic functions F(), G() and H() */
#define F(x, y, z)	((x) ^ (y) ^ (z))
#define G(x, y, z)	(((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)	(((x) | ~(y)) ^ (z))
#define I(x, y, z)	(((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z)	((x) ^ ((y) | ~(z)))

/* the eight basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)	{			\
      (a) += F((b), (c), (d)) + (x);			\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define GG(a, b, c, d, e, x, s)	{			\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define HH(a, b, c, d, e, x, s)	{			\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define II(a, b, c, d, e, x, s)	{			\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcU;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define JJ(a, b, c, d, e, x, s)	{			\
      (a) += J((b), (c), (d)) + (x) + 0xa953fd4eU;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define FFF(a, b, c, d, e, x, s)	{		\
      (a) += F((b), (c), (d)) + (x);			\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define GGG(a, b, c, d, e, x, s)	{		\
      (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define HHH(a, b, c, d, e, x, s)	{		\
      (a) += H((b), (c), (d)) + (x) + 0x6d703ef3U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define III(a, b, c, d, e, x, s)	{		\
      (a) += I((b), (c), (d)) + (x) + 0x5c4dd124U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}
#define JJJ(a, b, c, d, e, x, s)	{		\
      (a) += J((b), (c), (d)) + (x) + 0x50a28be6U;	\
      (a) = ROL((a), (s)) + (e);			\
      (c) = ROL((c), 10);				\
}

/********************************************************************/

void RMD160Init(context)
	RMD160_CTX *context;
{

	/* ripemd-160 initialization constants */
	context->state[0] = 0x67452301U;
	context->state[1] = 0xefcdab89U;
	context->state[2] = 0x98badcfeU;
	context->state[3] = 0x10325476U;
	context->state[4] = 0xc3d2e1f0U;
	context->length[0] = context->length[1] = 0;
	context->buflen = 0;
}

/********************************************************************/

void RMD160Transform(state, block)
	u_int32_t state[5];
	const u_int32_t block[16];
{
	u_int32_t aa = state[0],  bb = state[1],  cc = state[2],
	    dd = state[3],  ee = state[4];
	u_int32_t aaa = state[0], bbb = state[1], ccc = state[2],
	    ddd = state[3], eee = state[4];

	/* round 1 */
	FF(aa, bb, cc, dd, ee, block[ 0], 11);
	FF(ee, aa, bb, cc, dd, block[ 1], 14);
	FF(dd, ee, aa, bb, cc, block[ 2], 15);
	FF(cc, dd, ee, aa, bb, block[ 3], 12);
	FF(bb, cc, dd, ee, aa, block[ 4],  5);
	FF(aa, bb, cc, dd, ee, block[ 5],  8);
	FF(ee, aa, bb, cc, dd, block[ 6],  7);
	FF(dd, ee, aa, bb, cc, block[ 7],  9);
	FF(cc, dd, ee, aa, bb, block[ 8], 11);
	FF(bb, cc, dd, ee, aa, block[ 9], 13);
	FF(aa, bb, cc, dd, ee, block[10], 14);
	FF(ee, aa, bb, cc, dd, block[11], 15);
	FF(dd, ee, aa, bb, cc, block[12],  6);
	FF(cc, dd, ee, aa, bb, block[13],  7);
	FF(bb, cc, dd, ee, aa, block[14],  9);
	FF(aa, bb, cc, dd, ee, block[15],  8);

	/* round 2 */
	GG(ee, aa, bb, cc, dd, block[ 7],  7);
	GG(dd, ee, aa, bb, cc, block[ 4],  6);
	GG(cc, dd, ee, aa, bb, block[13],  8);
	GG(bb, cc, dd, ee, aa, block[ 1], 13);
	GG(aa, bb, cc, dd, ee, block[10], 11);
	GG(ee, aa, bb, cc, dd, block[ 6],  9);
	GG(dd, ee, aa, bb, cc, block[15],  7);
	GG(cc, dd, ee, aa, bb, block[ 3], 15);
	GG(bb, cc, dd, ee, aa, block[12],  7);
	GG(aa, bb, cc, dd, ee, block[ 0], 12);
	GG(ee, aa, bb, cc, dd, block[ 9], 15);
	GG(dd, ee, aa, bb, cc, block[ 5],  9);
	GG(cc, dd, ee, aa, bb, block[ 2], 11);
	GG(bb, cc, dd, ee, aa, block[14],  7);
	GG(aa, bb, cc, dd, ee, block[11], 13);
	GG(ee, aa, bb, cc, dd, block[ 8], 12);

	/* round 3 */
	HH(dd, ee, aa, bb, cc, block[ 3], 11);
	HH(cc, dd, ee, aa, bb, block[10], 13);
	HH(bb, cc, dd, ee, aa, block[14],  6);
	HH(aa, bb, cc, dd, ee, block[ 4],  7);
	HH(ee, aa, bb, cc, dd, block[ 9], 14);
	HH(dd, ee, aa, bb, cc, block[15],  9);
	HH(cc, dd, ee, aa, bb, block[ 8], 13);
	HH(bb, cc, dd, ee, aa, block[ 1], 15);
	HH(aa, bb, cc, dd, ee, block[ 2], 14);
	HH(ee, aa, bb, cc, dd, block[ 7],  8);
	HH(dd, ee, aa, bb, cc, block[ 0], 13);
	HH(cc, dd, ee, aa, bb, block[ 6],  6);
	HH(bb, cc, dd, ee, aa, block[13],  5);
	HH(aa, bb, cc, dd, ee, block[11], 12);
	HH(ee, aa, bb, cc, dd, block[ 5],  7);
	HH(dd, ee, aa, bb, cc, block[12],  5);

	/* round 4 */
	II(cc, dd, ee, aa, bb, block[ 1], 11);
	II(bb, cc, dd, ee, aa, block[ 9], 12);
	II(aa, bb, cc, dd, ee, block[11], 14);
	II(ee, aa, bb, cc, dd, block[10], 15);
	II(dd, ee, aa, bb, cc, block[ 0], 14);
	II(cc, dd, ee, aa, bb, block[ 8], 15);
	II(bb, cc, dd, ee, aa, block[12],  9);
	II(aa, bb, cc, dd, ee, block[ 4],  8);
	II(ee, aa, bb, cc, dd, block[13],  9);
	II(dd, ee, aa, bb, cc, block[ 3], 14);
	II(cc, dd, ee, aa, bb, block[ 7],  5);
	II(bb, cc, dd, ee, aa, block[15],  6);
	II(aa, bb, cc, dd, ee, block[14],  8);
	II(ee, aa, bb, cc, dd, block[ 5],  6);
	II(dd, ee, aa, bb, cc, block[ 6],  5);
	II(cc, dd, ee, aa, bb, block[ 2], 12);

	/* round 5 */
	JJ(bb, cc, dd, ee, aa, block[ 4],  9);
	JJ(aa, bb, cc, dd, ee, block[ 0], 15);
	JJ(ee, aa, bb, cc, dd, block[ 5],  5);
	JJ(dd, ee, aa, bb, cc, block[ 9], 11);
	JJ(cc, dd, ee, aa, bb, block[ 7],  6);
	JJ(bb, cc, dd, ee, aa, block[12],  8);
	JJ(aa, bb, cc, dd, ee, block[ 2], 13);
	JJ(ee, aa, bb, cc, dd, block[10], 12);
	JJ(dd, ee, aa, bb, cc, block[14],  5);
	JJ(cc, dd, ee, aa, bb, block[ 1], 12);
	JJ(bb, cc, dd, ee, aa, block[ 3], 13);
	JJ(aa, bb, cc, dd, ee, block[ 8], 14);
	JJ(ee, aa, bb, cc, dd, block[11], 11);
	JJ(dd, ee, aa, bb, cc, block[ 6],  8);
	JJ(cc, dd, ee, aa, bb, block[15],  5);
	JJ(bb, cc, dd, ee, aa, block[13],  6);

	/* parallel round 1 */
	JJJ(aaa, bbb, ccc, ddd, eee, block[ 5],  8);
	JJJ(eee, aaa, bbb, ccc, ddd, block[14],  9);
	JJJ(ddd, eee, aaa, bbb, ccc, block[ 7],  9);
	JJJ(ccc, ddd, eee, aaa, bbb, block[ 0], 11);
	JJJ(bbb, ccc, ddd, eee, aaa, block[ 9], 13);
	JJJ(aaa, bbb, ccc, ddd, eee, block[ 2], 15);
	JJJ(eee, aaa, bbb, ccc, ddd, block[11], 15);
	JJJ(ddd, eee, aaa, bbb, ccc, block[ 4],  5);
	JJJ(ccc, ddd, eee, aaa, bbb, block[13],  7);
	JJJ(bbb, ccc, ddd, eee, aaa, block[ 6],  7);
	JJJ(aaa, bbb, ccc, ddd, eee, block[15],  8);
	JJJ(eee, aaa, bbb, ccc, ddd, block[ 8], 11);
	JJJ(ddd, eee, aaa, bbb, ccc, block[ 1], 14);
	JJJ(ccc, ddd, eee, aaa, bbb, block[10], 14);
	JJJ(bbb, ccc, ddd, eee, aaa, block[ 3], 12);
	JJJ(aaa, bbb, ccc, ddd, eee, block[12],  6);

	/* parallel round 2 */
	III(eee, aaa, bbb, ccc, ddd, block[ 6],  9);
	III(ddd, eee, aaa, bbb, ccc, block[11], 13);
	III(ccc, ddd, eee, aaa, bbb, block[ 3], 15);
	III(bbb, ccc, ddd, eee, aaa, block[ 7],  7);
	III(aaa, bbb, ccc, ddd, eee, block[ 0], 12);
	III(eee, aaa, bbb, ccc, ddd, block[13],  8);
	III(ddd, eee, aaa, bbb, ccc, block[ 5],  9);
	III(ccc, ddd, eee, aaa, bbb, block[10], 11);
	III(bbb, ccc, ddd, eee, aaa, block[14],  7);
	III(aaa, bbb, ccc, ddd, eee, block[15],  7);
	III(eee, aaa, bbb, ccc, ddd, block[ 8], 12);
	III(ddd, eee, aaa, bbb, ccc, block[12],  7);
	III(ccc, ddd, eee, aaa, bbb, block[ 4],  6);
	III(bbb, ccc, ddd, eee, aaa, block[ 9], 15);
	III(aaa, bbb, ccc, ddd, eee, block[ 1], 13);
	III(eee, aaa, bbb, ccc, ddd, block[ 2], 11);

	/* parallel round 3 */
	HHH(ddd, eee, aaa, bbb, ccc, block[15],  9);
	HHH(ccc, ddd, eee, aaa, bbb, block[ 5],  7);
	HHH(bbb, ccc, ddd, eee, aaa, block[ 1], 15);
	HHH(aaa, bbb, ccc, ddd, eee, block[ 3], 11);
	HHH(eee, aaa, bbb, ccc, ddd, block[ 7],  8);
	HHH(ddd, eee, aaa, bbb, ccc, block[14],  6);
	HHH(ccc, ddd, eee, aaa, bbb, block[ 6],  6);
	HHH(bbb, ccc, ddd, eee, aaa, block[ 9], 14);
	HHH(aaa, bbb, ccc, ddd, eee, block[11], 12);
	HHH(eee, aaa, bbb, ccc, ddd, block[ 8], 13);
	HHH(ddd, eee, aaa, bbb, ccc, block[12],  5);
	HHH(ccc, ddd, eee, aaa, bbb, block[ 2], 14);
	HHH(bbb, ccc, ddd, eee, aaa, block[10], 13);
	HHH(aaa, bbb, ccc, ddd, eee, block[ 0], 13);
	HHH(eee, aaa, bbb, ccc, ddd, block[ 4],  7);
	HHH(ddd, eee, aaa, bbb, ccc, block[13],  5);

	/* parallel round 4 */
	GGG(ccc, ddd, eee, aaa, bbb, block[ 8], 15);
	GGG(bbb, ccc, ddd, eee, aaa, block[ 6],  5);
	GGG(aaa, bbb, ccc, ddd, eee, block[ 4],  8);
	GGG(eee, aaa, bbb, ccc, ddd, block[ 1], 11);
	GGG(ddd, eee, aaa, bbb, ccc, block[ 3], 14);
	GGG(ccc, ddd, eee, aaa, bbb, block[11], 14);
	GGG(bbb, ccc, ddd, eee, aaa, block[15],  6);
	GGG(aaa, bbb, ccc, ddd, eee, block[ 0], 14);
	GGG(eee, aaa, bbb, ccc, ddd, block[ 5],  6);
	GGG(ddd, eee, aaa, bbb, ccc, block[12],  9);
	GGG(ccc, ddd, eee, aaa, bbb, block[ 2], 12);
	GGG(bbb, ccc, ddd, eee, aaa, block[13],  9);
	GGG(aaa, bbb, ccc, ddd, eee, block[ 9], 12);
	GGG(eee, aaa, bbb, ccc, ddd, block[ 7],  5);
	GGG(ddd, eee, aaa, bbb, ccc, block[10], 15);
	GGG(ccc, ddd, eee, aaa, bbb, block[14],  8);

	/* parallel round 5 */
	FFF(bbb, ccc, ddd, eee, aaa, block[12] ,  8);
	FFF(aaa, bbb, ccc, ddd, eee, block[15] ,  5);
	FFF(eee, aaa, bbb, ccc, ddd, block[10] , 12);
	FFF(ddd, eee, aaa, bbb, ccc, block[ 4] ,  9);
	FFF(ccc, ddd, eee, aaa, bbb, block[ 1] , 12);
	FFF(bbb, ccc, ddd, eee, aaa, block[ 5] ,  5);
	FFF(aaa, bbb, ccc, ddd, eee, block[ 8] , 14);
	FFF(eee, aaa, bbb, ccc, ddd, block[ 7] ,  6);
	FFF(ddd, eee, aaa, bbb, ccc, block[ 6] ,  8);
	FFF(ccc, ddd, eee, aaa, bbb, block[ 2] , 13);
	FFF(bbb, ccc, ddd, eee, aaa, block[13] ,  6);
	FFF(aaa, bbb, ccc, ddd, eee, block[14] ,  5);
	FFF(eee, aaa, bbb, ccc, ddd, block[ 0] , 15);
	FFF(ddd, eee, aaa, bbb, ccc, block[ 3] , 13);
	FFF(ccc, ddd, eee, aaa, bbb, block[ 9] , 11);
	FFF(bbb, ccc, ddd, eee, aaa, block[11] , 11);

	/* combine results */
	ddd += cc + state[1];		/* final result for state[0] */
	state[1] = state[2] + dd + eee;
	state[2] = state[3] + ee + aaa;
	state[3] = state[4] + aa + bbb;
	state[4] = state[0] + bb + ccc;
	state[0] = ddd;
}

/********************************************************************/

void RMD160Update(context, data, nbytes)
	RMD160_CTX *context;
	const u_char *data;
	u_int32_t nbytes;
{
	u_int32_t X[16];
	u_int32_t ofs = 0;
	u_int32_t i;
#if BYTE_ORDER != LITTLE_ENDIAN
	u_int32_t j;
#endif

	/* update length[] */
	if (context->length[0] + nbytes < context->length[0])
		context->length[1]++;		/* overflow to msb of length */
	context->length[0] += nbytes;

	bzero(X, sizeof(X));

        if ( context->buflen + nbytes < 64 )
        {
		bcopy(data, context->bbuffer + context->buflen, nbytes);
                context->buflen += nbytes;
        }
        else
        {
                /* process first block */
                ofs = 64 - context->buflen;
		bcopy(data, context->bbuffer + context->buflen, ofs);
#if BYTE_ORDER == LITTLE_ENDIAN
		bcopy(context->bbuffer, X, sizeof(X));
#else
                for (j=0; j < 16; j++)
                        X[j] = BYTES_TO_DWORD(context->bbuffer + (4 * j));
#endif
                RMD160Transform(context->state, X);
                nbytes -= ofs;

                /* process remaining complete blocks */
                for (i = 0; i < (nbytes >> 6); i++) {
#if BYTE_ORDER == LITTLE_ENDIAN
			bcopy(data + (64 * i) + ofs, X, sizeof(X));
#else
                        for (j=0; j < 16; j++)
                                X[j] = BYTES_TO_DWORD(data + (64 * i) + (4 * j) + ofs);
#endif
                        RMD160Transform(context->state, X);
                }

                /*
                 * Put last bytes from data into context's buffer
                 */
                context->buflen = nbytes & 63;
		bcopy(data + (64 * i) + ofs, context->bbuffer, context->buflen);
        }
}

/********************************************************************/

void RMD160Final(digest, context)
	u_char digest[20];
	RMD160_CTX *context;
{
	u_int32_t i;
	u_int32_t X[16];
#if BYTE_ORDER != LITTLE_ENDIAN
	u_int32_t j;
#endif

	/* append the bit m_n == 1 */
	context->bbuffer[context->buflen] = '\200';


	bzero(context->bbuffer + context->buflen + 1, 63 - context->buflen);
#if BYTE_ORDER == LITTLE_ENDIAN
	bcopy(context->bbuffer, X, sizeof(X));
#else
	for (j=0; j < 16; j++)
		X[j] = BYTES_TO_DWORD(context->bbuffer + (4 * j));
#endif
	if ((context->buflen) > 55) {
		/* length goes to next block */
		RMD160Transform(context->state, X);
		bzero(X, sizeof(X));
	}

	/* append length in bits */
	X[14] = context->length[0] << 3;
	X[15] = (context->length[0] >> 29) |
	    (context->length[1] << 3);
	RMD160Transform(context->state, X);

	if (digest != NULL) {
		for (i = 0; i < 20; i += 4) {
			/* extracts the 8 least significant bits. */
			digest[i]     =  context->state[i>>2];
			digest[i + 1] = (context->state[i>>2] >>  8);
			digest[i + 2] = (context->state[i>>2] >> 16);
			digest[i + 3] = (context->state[i>>2] >> 24);
		}
	}
}

/************************ end of file rmd160.c **********************/
/*	$OpenBSD$	*/

/* lib/des/set_key.c */
/* Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* set_key.c v 1.4 eay 24/9/91
 * 1.4 Speed up by 400% :-)
 * 1.3 added register declarations.
 * 1.2 unrolled make_key_sched a bit more
 * 1.1 added norm_expand_bits
 * 1.0 First working version
 */
#include "des_locl.h"
#include "podd.h"
#include "sk.h"

#ifdef PROTO
static int check_parity(des_cblock (*key));
#else
static int check_parity();
#endif

int des_check_key=0;

void des_set_odd_parity(key)
des_cblock (*key);
	{
	int i;

	for (i=0; i<DES_KEY_SZ; i++)
		(*key)[i]=odd_parity[(*key)[i]];
	}

static int check_parity(key)
des_cblock (*key);
	{
	int i;

	for (i=0; i<DES_KEY_SZ; i++)
		{
		if ((*key)[i] != odd_parity[(*key)[i]])
			return(0);
		}
	return(1);
	}

/* Weak and semi week keys as take from
 * %A D.W. Davies
 * %A W.L. Price
 * %T Security for Computer Networks
 * %I John Wiley & Sons
 * %D 1984
 * Many thanks to smb@ulysses.att.com (Steven Bellovin) for the reference
 * (and actual cblock values).
 */
#define NUM_WEAK_KEY	16
static des_cblock weak_keys[NUM_WEAK_KEY]={
	/* weak keys */
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
	{0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
	{0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F},
	{0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0},
	/* semi-weak keys */
	{0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
	{0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
	{0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
	{0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
	{0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
	{0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
	{0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
	{0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
	{0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
	{0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
	{0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
	{0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}};

int des_is_weak_key(key)
des_cblock (*key);
	{
	int i;

	for (i=0; i<NUM_WEAK_KEY; i++)
		/* Added == 0 to comparision, I obviously don't run
		 * this section very often :-(, thanks to
		 * engineering@MorningStar.Com for the fix
		 * eay 93/06/29 */
		if (bcmp(weak_keys[i],key,sizeof(des_cblock)) == 0) return(1);
	return(0);
	}

/* NOW DEFINED IN des_local.h
 * See ecb_encrypt.c for a pseudo description of these macros. 
 * #define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
 * 	(b)^=(t),\
 * 	(a)=((a)^((t)<<(n))))
 */

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
	(a)=(a)^(t)^(t>>(16-(n))))

static int shifts2[16]={0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};

/* return 0 if key parity is odd (correct),
 * return -1 if key parity error,
 * return -2 if illegal weak key.
 */
int des_set_key(key, schedule)
des_cblock (*key);
des_key_schedule schedule;
	{
	register unsigned long c,d,t,s;
	register unsigned char *in;
	register unsigned long *k;
	register int i;

	if (des_check_key)
		{
		if (!check_parity(key))
			return(-1);

		if (des_is_weak_key(key))
			return(-2);
		}

	k=(unsigned long *)schedule;
	in=(unsigned char *)key;

	c2l(in,c);
	c2l(in,d);

	/* do PC1 in 60 simple operations */ 
/*	PERM_OP(d,c,t,4,0x0f0f0f0fL);
	HPERM_OP(c,t,-2, 0xcccc0000L);
	HPERM_OP(c,t,-1, 0xaaaa0000L);
	HPERM_OP(c,t, 8, 0x00ff0000L);
	HPERM_OP(c,t,-1, 0xaaaa0000L);
	HPERM_OP(d,t,-8, 0xff000000L);
	HPERM_OP(d,t, 8, 0x00ff0000L);
	HPERM_OP(d,t, 2, 0x33330000L);
	d=((d&0x00aa00aaL)<<7L)|((d&0x55005500L)>>7L)|(d&0xaa55aa55L);
	d=(d>>8)|((c&0xf0000000L)>>4);
	c&=0x0fffffffL; */

	/* I now do it in 47 simple operations :-)
	 * Thanks to John Fletcher (john_fletcher@lccmail.ocf.llnl.gov)
	 * for the inspiration. :-) */
	PERM_OP (d,c,t,4,0x0f0f0f0fL);
	HPERM_OP(c,t,-2,0xcccc0000L);
	HPERM_OP(d,t,-2,0xcccc0000L);
	PERM_OP (d,c,t,1,0x55555555L);
	PERM_OP (c,d,t,8,0x00ff00ffL);
	PERM_OP (d,c,t,1,0x55555555L);
	d=	(((d&0x000000ffL)<<16L)| (d&0x0000ff00L)     |
		 ((d&0x00ff0000L)>>16L)|((c&0xf0000000L)>>4L));
	c&=0x0fffffffL;

	for (i=0; i<ITERATIONS; i++)
		{
		if (shifts2[i])
			{ c=((c>>2L)|(c<<26L)); d=((d>>2L)|(d<<26L)); }
		else
			{ c=((c>>1L)|(c<<27L)); d=((d>>1L)|(d<<27L)); }
		c&=0x0fffffffL;
		d&=0x0fffffffL;
		/* could be a few less shifts but I am to lazy at this
		 * point in time to investigate */
		s=	des_skb[0][ (c    )&0x3f                ]|
			des_skb[1][((c>> 6)&0x03)|((c>> 7L)&0x3c)]|
			des_skb[2][((c>>13)&0x0f)|((c>>14L)&0x30)]|
			des_skb[3][((c>>20)&0x01)|((c>>21L)&0x06) |
						  ((c>>22L)&0x38)];
		t=	des_skb[4][ (d    )&0x3f                ]|
			des_skb[5][((d>> 7L)&0x03)|((d>> 8L)&0x3c)]|
			des_skb[6][ (d>>15L)&0x3f                ]|
			des_skb[7][((d>>21L)&0x0f)|((d>>22L)&0x30)];

		/* table contained 0213 4657 */
		*(k++)=((t<<16L)|(s&0x0000ffffL))&0xffffffffL;
		s=     ((s>>16L)|(t&0xffff0000L));
		
		s=(s<<4L)|(s>>28L);
		*(k++)=s&0xffffffffL;
		}
	return(0);
	}

int des_key_sched(key, schedule)
des_cblock (*key);
des_key_schedule schedule;
	{
	return(des_set_key(key,schedule));
	}
/*	$OpenBSD$	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 * 
 * Test Vectors (from FIPS PUB 180-1)
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */

#define SHA1HANDSOFF

#include <sys/param.h>
#include <sys/systm.h>

#include <crypto/sha1.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(u_int32_t state[5], unsigned char buffer[64])
{
u_int32_t a, b, c, d, e;
typedef union {
    unsigned char c[64];
    unsigned int l[16];
} CHAR64LONG16;
CHAR64LONG16* block;
#ifdef SHA1HANDSOFF
    static unsigned char workspace[64];

    block = (CHAR64LONG16 *)workspace;
    bcopy(buffer, block, 64);
#else
    block = (CHAR64LONG16 *)buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
}


/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX *context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX *context, unsigned char *data, unsigned int len)
{
unsigned int i;
unsigned int j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j) context->count[1] += (len>>29)+1;
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        bcopy(data, &context->buffer[j], (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    bcopy(&data[i], &context->buffer[j], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX *context)
{
unsigned int i;
unsigned char finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    SHA1Update(context, (unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1Update(context, (unsigned char *)"\0", 1);
    }
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */

    if (digest)
      for (i = 0; i < 20; i++) {
          digest[i] = (unsigned char)
           ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
      }
#if 0	/* We want to use this for "keyfill" */
    /* Wipe variables */
    i = 0;
    bzero(context->buffer, 64);
    bzero(context->state, 20);
    bzero(context->count, 8);
    bzero(&finalcount, 8);
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
    SHA1Transform(context->state, context->buffer);
#endif
#endif
}
/*	$OpenBSD$	*/

/* 
 * Further optimized test implementation of SKIPJACK algorithm 
 * Mark Tillotson <markt@chaos.org.uk>, 25 June 98
 * Optimizations suit RISC (lots of registers) machine best.
 *
 * based on unoptimized implementation of
 * Panu Rissanen <bande@lut.fi> 960624
 *
 * SKIPJACK and KEA Algorithm Specifications 
 * Version 2.0 
 * 29 May 1998
*/

#include <sys/param.h>
#include <crypto/skipjack.h>
#include <sys/malloc.h>

static const u_int8_t ftable[0x100] =
{ 
	0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 
	0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9, 
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 
	0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28, 
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 
	0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53, 
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 
	0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2, 
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 
	0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 
	0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90, 
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 
	0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76, 
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 
	0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d, 
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 
	0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18, 
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 
	0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4, 
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 
	0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40, 
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 
	0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5, 
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 
	0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2, 
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 
	0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8, 
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 
	0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac, 
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 
	0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
};

/*
 * For each key byte generate a table to represent the function 
 *    ftable [in ^ keybyte]
 *
 * These tables used to save an XOR in each stage of the G-function
 * the tables are hopefully pointed to by register allocated variables
 * k0, k1..k9
 */
void
subkey_table_gen (u_int8_t *key, u_int8_t **key_tables)
{
	int i, k;

	for (k = 0; k < 10; k++) {
		u_int8_t   key_byte = key [k];
		u_int8_t * table = (u_int8_t *) malloc(0x100, M_XDATA, M_WAITOK);
		/* XXX */

		key_tables [k] = table;
		for (i = 0; i < 0x100; i++)
			table [i] = ftable [i ^ key_byte];
	}
}


#define g(k0, k1, k2, k3, ih, il, oh, ol) \
{ \
	oh = k##k0 [il] ^ ih; \
	ol = k##k1 [oh] ^ il; \
	oh = k##k2 [ol] ^ oh; \
	ol = k##k3 [oh] ^ ol; \
}

#define g0(ih, il, oh, ol) g(0, 1, 2, 3, ih, il, oh, ol)
#define g4(ih, il, oh, ol) g(4, 5, 6, 7, ih, il, oh, ol)
#define g8(ih, il, oh, ol) g(8, 9, 0, 1, ih, il, oh, ol)
#define g2(ih, il, oh, ol) g(2, 3, 4, 5, ih, il, oh, ol)
#define g6(ih, il, oh, ol) g(6, 7, 8, 9, ih, il, oh, ol)

 
#define g_inv(k0, k1, k2, k3, ih, il, oh, ol) \
{ \
	ol = k##k3 [ih] ^ il; \
	oh = k##k2 [ol] ^ ih; \
	ol = k##k1 [oh] ^ ol; \
	oh = k##k0 [ol] ^ oh; \
}


#define g0_inv(ih, il, oh, ol) g_inv(0, 1, 2, 3, ih, il, oh, ol)
#define g4_inv(ih, il, oh, ol) g_inv(4, 5, 6, 7, ih, il, oh, ol)
#define g8_inv(ih, il, oh, ol) g_inv(8, 9, 0, 1, ih, il, oh, ol)
#define g2_inv(ih, il, oh, ol) g_inv(2, 3, 4, 5, ih, il, oh, ol)
#define g6_inv(ih, il, oh, ol) g_inv(6, 7, 8, 9, ih, il, oh, ol)

/* optimized version of Skipjack algorithm
 *
 * the appropriate g-function is inlined for each round
 *
 * the data movement is minimized by rotating the names of the 
 * variables w1..w4, not their contents (saves 3 moves per round)
 *
 * the loops are completely unrolled (needed to staticize choice of g)
 *
 * compiles to about 470 instructions on a Sparc (gcc -O)
 * which is about 58 instructions per byte, 14 per round.
 * gcc seems to leave in some unnecessary and with 0xFF operations
 * but only in the latter part of the functions.  Perhaps it
 * runs out of resources to properly optimize long inlined function?
 * in theory should get about 11 instructions per round, not 14
 */

void
skipjack_forwards(u_int8_t *plain, u_int8_t *cipher, u_int8_t **key_tables)
{
	u_int8_t wh1 = plain[0];  u_int8_t wl1 = plain[1];
	u_int8_t wh2 = plain[2];  u_int8_t wl2 = plain[3];
	u_int8_t wh3 = plain[4];  u_int8_t wl3 = plain[5];
	u_int8_t wh4 = plain[6];  u_int8_t wl4 = plain[7];

	u_int8_t * k0 = key_tables [0];
	u_int8_t * k1 = key_tables [1];
	u_int8_t * k2 = key_tables [2];
	u_int8_t * k3 = key_tables [3];
	u_int8_t * k4 = key_tables [4];
	u_int8_t * k5 = key_tables [5];
	u_int8_t * k6 = key_tables [6];
	u_int8_t * k7 = key_tables [7];
	u_int8_t * k8 = key_tables [8];
	u_int8_t * k9 = key_tables [9];

	/* first 8 rounds */
	g0 (wh1,wl1, wh1,wl1); wl4 ^= wl1 ^ 1; wh4 ^= wh1;
	g4 (wh4,wl4, wh4,wl4); wl3 ^= wl4 ^ 2; wh3 ^= wh4;
	g8 (wh3,wl3, wh3,wl3); wl2 ^= wl3 ^ 3; wh2 ^= wh3;
	g2 (wh2,wl2, wh2,wl2); wl1 ^= wl2 ^ 4; wh1 ^= wh2;
	g6 (wh1,wl1, wh1,wl1); wl4 ^= wl1 ^ 5; wh4 ^= wh1;
	g0 (wh4,wl4, wh4,wl4); wl3 ^= wl4 ^ 6; wh3 ^= wh4;
	g4 (wh3,wl3, wh3,wl3); wl2 ^= wl3 ^ 7; wh2 ^= wh3;
	g8 (wh2,wl2, wh2,wl2); wl1 ^= wl2 ^ 8; wh1 ^= wh2;

	/* second 8 rounds */
	wh2 ^= wh1; wl2 ^= wl1 ^ 9 ; g2 (wh1,wl1, wh1,wl1);
	wh1 ^= wh4; wl1 ^= wl4 ^ 10; g6 (wh4,wl4, wh4,wl4);
	wh4 ^= wh3; wl4 ^= wl3 ^ 11; g0 (wh3,wl3, wh3,wl3);
	wh3 ^= wh2; wl3 ^= wl2 ^ 12; g4 (wh2,wl2, wh2,wl2);
	wh2 ^= wh1; wl2 ^= wl1 ^ 13; g8 (wh1,wl1, wh1,wl1);
	wh1 ^= wh4; wl1 ^= wl4 ^ 14; g2 (wh4,wl4, wh4,wl4);
	wh4 ^= wh3; wl4 ^= wl3 ^ 15; g6 (wh3,wl3, wh3,wl3);
	wh3 ^= wh2; wl3 ^= wl2 ^ 16; g0 (wh2,wl2, wh2,wl2);

	/* third 8 rounds */
	g4 (wh1,wl1, wh1,wl1); wl4 ^= wl1 ^ 17; wh4 ^= wh1;
	g8 (wh4,wl4, wh4,wl4); wl3 ^= wl4 ^ 18; wh3 ^= wh4;
	g2 (wh3,wl3, wh3,wl3); wl2 ^= wl3 ^ 19; wh2 ^= wh3;
	g6 (wh2,wl2, wh2,wl2); wl1 ^= wl2 ^ 20; wh1 ^= wh2;
	g0 (wh1,wl1, wh1,wl1); wl4 ^= wl1 ^ 21; wh4 ^= wh1;
	g4 (wh4,wl4, wh4,wl4); wl3 ^= wl4 ^ 22; wh3 ^= wh4;
	g8 (wh3,wl3, wh3,wl3); wl2 ^= wl3 ^ 23; wh2 ^= wh3;
	g2 (wh2,wl2, wh2,wl2); wl1 ^= wl2 ^ 24; wh1 ^= wh2;

	/* last 8 rounds */
	wh2 ^= wh1; wl2 ^= wl1 ^ 25; g6 (wh1,wl1, wh1,wl1);
	wh1 ^= wh4; wl1 ^= wl4 ^ 26; g0 (wh4,wl4, wh4,wl4);
	wh4 ^= wh3; wl4 ^= wl3 ^ 27; g4 (wh3,wl3, wh3,wl3);
	wh3 ^= wh2; wl3 ^= wl2 ^ 28; g8 (wh2,wl2, wh2,wl2);
	wh2 ^= wh1; wl2 ^= wl1 ^ 29; g2 (wh1,wl1, wh1,wl1);
	wh1 ^= wh4; wl1 ^= wl4 ^ 30; g6 (wh4,wl4, wh4,wl4);
	wh4 ^= wh3; wl4 ^= wl3 ^ 31; g0 (wh3,wl3, wh3,wl3);
	wh3 ^= wh2; wl3 ^= wl2 ^ 32; g4 (wh2,wl2, wh2,wl2);

	/* pack into byte vector */
	cipher [0] = wh1;  cipher [1] = wl1;
	cipher [2] = wh2;  cipher [3] = wl2;
	cipher [4] = wh3;  cipher [5] = wl3;
	cipher [6] = wh4;  cipher [7] = wl4;
}


void
skipjack_backwards (u_int8_t *cipher, u_int8_t *plain, u_int8_t **key_tables)
{
	/* setup 4 16-bit portions */
	u_int8_t wh1 = cipher[0];  u_int8_t wl1 = cipher[1];
	u_int8_t wh2 = cipher[2];  u_int8_t wl2 = cipher[3];
	u_int8_t wh3 = cipher[4];  u_int8_t wl3 = cipher[5];
	u_int8_t wh4 = cipher[6];  u_int8_t wl4 = cipher[7];

	u_int8_t * k0 = key_tables [0];
	u_int8_t * k1 = key_tables [1];
	u_int8_t * k2 = key_tables [2];
	u_int8_t * k3 = key_tables [3];
	u_int8_t * k4 = key_tables [4];
	u_int8_t * k5 = key_tables [5];
	u_int8_t * k6 = key_tables [6];
	u_int8_t * k7 = key_tables [7];
	u_int8_t * k8 = key_tables [8];
	u_int8_t * k9 = key_tables [9];

	/* first 8 rounds */
	g4_inv (wh2,wl2, wh2,wl2); wl3 ^= wl2 ^ 32; wh3 ^= wh2;
	g0_inv (wh3,wl3, wh3,wl3); wl4 ^= wl3 ^ 31; wh4 ^= wh3;
	g6_inv (wh4,wl4, wh4,wl4); wl1 ^= wl4 ^ 30; wh1 ^= wh4;
	g2_inv (wh1,wl1, wh1,wl1); wl2 ^= wl1 ^ 29; wh2 ^= wh1;
	g8_inv (wh2,wl2, wh2,wl2); wl3 ^= wl2 ^ 28; wh3 ^= wh2;
	g4_inv (wh3,wl3, wh3,wl3); wl4 ^= wl3 ^ 27; wh4 ^= wh3;
	g0_inv (wh4,wl4, wh4,wl4); wl1 ^= wl4 ^ 26; wh1 ^= wh4;
	g6_inv (wh1,wl1, wh1,wl1); wl2 ^= wl1 ^ 25; wh2 ^= wh1;

	/* second 8 rounds */
	wh1 ^= wh2; wl1 ^= wl2 ^ 24; g2_inv (wh2,wl2, wh2,wl2);
	wh2 ^= wh3; wl2 ^= wl3 ^ 23; g8_inv (wh3,wl3, wh3,wl3);
	wh3 ^= wh4; wl3 ^= wl4 ^ 22; g4_inv (wh4,wl4, wh4,wl4);
	wh4 ^= wh1; wl4 ^= wl1 ^ 21; g0_inv (wh1,wl1, wh1,wl1);
	wh1 ^= wh2; wl1 ^= wl2 ^ 20; g6_inv (wh2,wl2, wh2,wl2);
	wh2 ^= wh3; wl2 ^= wl3 ^ 19; g2_inv (wh3,wl3, wh3,wl3);
	wh3 ^= wh4; wl3 ^= wl4 ^ 18; g8_inv (wh4,wl4, wh4,wl4);
	wh4 ^= wh1; wl4 ^= wl1 ^ 17; g4_inv (wh1,wl1, wh1,wl1);

	/* third 8 rounds */
	g0_inv (wh2,wl2, wh2,wl2); wl3 ^= wl2 ^ 16; wh3 ^= wh2;
	g6_inv (wh3,wl3, wh3,wl3); wl4 ^= wl3 ^ 15; wh4 ^= wh3;
	g2_inv (wh4,wl4, wh4,wl4); wl1 ^= wl4 ^ 14; wh1 ^= wh4;
	g8_inv (wh1,wl1, wh1,wl1); wl2 ^= wl1 ^ 13; wh2 ^= wh1;
	g4_inv (wh2,wl2, wh2,wl2); wl3 ^= wl2 ^ 12; wh3 ^= wh2;
	g0_inv (wh3,wl3, wh3,wl3); wl4 ^= wl3 ^ 11; wh4 ^= wh3;
	g6_inv (wh4,wl4, wh4,wl4); wl1 ^= wl4 ^ 10; wh1 ^= wh4;
	g2_inv (wh1,wl1, wh1,wl1); wl2 ^= wl1 ^ 9;  wh2 ^= wh1;

	/* last 8 rounds */
	wh1 ^= wh2; wl1 ^= wl2 ^ 8; g8_inv (wh2,wl2, wh2,wl2);
	wh2 ^= wh3; wl2 ^= wl3 ^ 7; g4_inv (wh3,wl3, wh3,wl3);
	wh3 ^= wh4; wl3 ^= wl4 ^ 6; g0_inv (wh4,wl4, wh4,wl4);
	wh4 ^= wh1; wl4 ^= wl1 ^ 5; g6_inv (wh1,wl1, wh1,wl1);
	wh1 ^= wh2; wl1 ^= wl2 ^ 4; g2_inv (wh2,wl2, wh2,wl2);
	wh2 ^= wh3; wl2 ^= wl3 ^ 3; g8_inv (wh3,wl3, wh3,wl3);
	wh3 ^= wh4; wl3 ^= wl4 ^ 2; g4_inv (wh4,wl4, wh4,wl4);
	wh4 ^= wh1; wl4 ^= wl1 ^ 1; g0_inv (wh1,wl1, wh1,wl1);

	/* pack into byte vector */
	plain [0] = wh1;  plain [1] = wl1;
	plain [2] = wh2;  plain [3] = wl2;
	plain [4] = wh3;  plain [5] = wl3;
	plain [6] = wh4;  plain [7] = wl4;
}
/*	$OpenBSD$	*/

/*
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr) and
 * Niels Provos (provos@physnet.uni-hamburg.de).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece,
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Additional features in 1999 by Angelos D. Keromytis.
 *
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 by John Ioannidis,
 * Angelos D. Keromytis and Niels Provos.
 *
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software.
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <machine/cpu.h>

#include <sys/md5k.h>
#include <crypto/sha1.h>
#include <crypto/rmd160.h>
#include <crypto/blf.h>
#include <crypto/cast.h>
#include <crypto/skipjack.h>
#include <crypto/rijndael.h>
#include <crypto/crypto.h>
#include <crypto/xform.h>

extern void des_ecb3_encrypt(caddr_t, caddr_t, caddr_t, caddr_t, caddr_t, int);
extern void des_ecb_encrypt(caddr_t, caddr_t, caddr_t, int);

void des_set_key(caddr_t, caddr_t);
void des1_setkey(u_int8_t **, u_int8_t *, int);
void des3_setkey(u_int8_t **, u_int8_t *, int);
void blf_setkey(u_int8_t **, u_int8_t *, int);
void cast5_setkey(u_int8_t **, u_int8_t *, int);
void skipjack_setkey(u_int8_t **, u_int8_t *, int);
void rijndael128_setkey(u_int8_t **, u_int8_t *, int);
void des1_encrypt(caddr_t, u_int8_t *);
void des3_encrypt(caddr_t, u_int8_t *);
void blf_encrypt(caddr_t, u_int8_t *);
void cast5_encrypt(caddr_t, u_int8_t *);
void skipjack_encrypt(caddr_t, u_int8_t *);
void rijndael128_encrypt(caddr_t, u_int8_t *);
void des1_decrypt(caddr_t, u_int8_t *);
void des3_decrypt(caddr_t, u_int8_t *);
void blf_decrypt(caddr_t, u_int8_t *);
void cast5_decrypt(caddr_t, u_int8_t *);
void skipjack_decrypt(caddr_t, u_int8_t *);
void rijndael128_decrypt(caddr_t, u_int8_t *);
void des1_zerokey(u_int8_t **);
void des3_zerokey(u_int8_t **);
void blf_zerokey(u_int8_t **);
void cast5_zerokey(u_int8_t **);
void skipjack_zerokey(u_int8_t **);
void rijndael128_zerokey(u_int8_t **);

int MD5Update_int(void *, u_int8_t *, u_int16_t);
int SHA1Update_int(void *, u_int8_t *, u_int16_t);
int RMD160Update_int(void *, u_int8_t *, u_int16_t);

/* Encryption instances */
struct enc_xform enc_xform_des =
{
    CRYPTO_DES_CBC, "DES",
    8, 8, 8, 8,
    des1_encrypt,
    des1_decrypt,
    des1_setkey,
    des1_zerokey,
};

struct enc_xform enc_xform_3des =
{
    CRYPTO_3DES_CBC, "3DES",
    8, 24, 24, 8,
    des3_encrypt,
    des3_decrypt,
    des3_setkey,
    des3_zerokey
};

struct enc_xform enc_xform_blf =
{
    CRYPTO_BLF_CBC, "Blowfish",
    8, 5, 56 /* 448 bits, max key */, 8,
    blf_encrypt,
    blf_decrypt,
    blf_setkey,
    blf_zerokey
};

struct enc_xform enc_xform_cast5 =
{
    CRYPTO_CAST_CBC, "CAST-128",
    8, 5, 16, 8,
    cast5_encrypt,
    cast5_decrypt,
    cast5_setkey,
    cast5_zerokey
};

struct enc_xform enc_xform_skipjack =
{
    CRYPTO_SKIPJACK_CBC, "Skipjack",
    8, 10, 10, 8,
    skipjack_encrypt,
    skipjack_decrypt,
    skipjack_setkey,
    skipjack_zerokey
};

struct enc_xform enc_xform_rijndael128 =
{
    CRYPTO_RIJNDAEL128_CBC, "Rijndael-128/AES",
    16, 8, 32, 16,
    rijndael128_encrypt,
    rijndael128_decrypt,
    rijndael128_setkey,
    rijndael128_zerokey,
};

/* Authentication instances */
struct auth_hash auth_hash_hmac_md5_96 =
{
    CRYPTO_MD5_HMAC, "HMAC-MD5",
    16, 16, 12, sizeof(MD5_CTX),
    (void (*) (void *)) MD5Init, MD5Update_int,
    (void (*) (u_int8_t *, void *)) MD5Final
};

struct auth_hash auth_hash_hmac_sha1_96 =
{
    CRYPTO_SHA1_HMAC, "HMAC-SHA1",
    20, 20, 12, sizeof(SHA1_CTX),
    (void (*) (void *)) SHA1Init, SHA1Update_int,
     (void (*) (u_int8_t *, void *)) SHA1Final
};

struct auth_hash auth_hash_hmac_ripemd_160_96 =
{
    CRYPTO_RIPEMD160_HMAC, "HMAC-RIPEMD-160",
    20, 20, 12, sizeof(RMD160_CTX),
    (void (*)(void *)) RMD160Init, RMD160Update_int,
    (void (*)(u_int8_t *, void *)) RMD160Final
};

struct auth_hash auth_hash_key_md5 =
{
    CRYPTO_MD5_KPDK, "Keyed MD5", 
    0, 16, 16, sizeof(MD5_CTX),
    (void (*)(void *)) MD5Init, MD5Update_int,
    (void (*)(u_int8_t *, void *)) MD5Final 
};

struct auth_hash auth_hash_key_sha1 =
{
    CRYPTO_SHA1_KPDK, "Keyed SHA1",
    0, 20, 20, sizeof(SHA1_CTX),
    (void (*)(void *)) SHA1Init, SHA1Update_int,
    (void (*)(u_int8_t *, void *)) SHA1Final 
};

/*
 * Encryption wrapper routines.
 */
void
des1_encrypt(caddr_t key, u_int8_t *blk)
{
    des_ecb_encrypt(blk, blk, key, 1);
}

void
des1_decrypt(caddr_t key, u_int8_t *blk)
{
    des_ecb_encrypt(blk, blk, key, 0);
}

void
des1_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, 128, M_XDATA, M_WAITOK);
    bzero(*sched, 128);
    des_set_key(key, *sched);
}

void
des1_zerokey(u_int8_t **sched)
{
    bzero(*sched, 128);
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

void
des3_encrypt(caddr_t key, u_int8_t *blk)
{
    des_ecb3_encrypt(blk, blk, key, key + 128, key + 256, 1);
}

void
des3_decrypt(caddr_t key, u_int8_t *blk)
{
    des_ecb3_encrypt(blk, blk, key + 256, key + 128, key, 0);
}

void
des3_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, 384, M_XDATA, M_WAITOK);
    bzero(*sched, 384);
    des_set_key(key, *sched);
    des_set_key(key + 8, *sched + 128);
    des_set_key(key + 16, *sched + 256);
}

void
des3_zerokey(u_int8_t **sched)
{
    bzero(*sched, 384);
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

void
blf_encrypt(caddr_t key, u_int8_t *blk)
{
    blf_ecb_encrypt((blf_ctx *) key, blk, 8);
}

void
blf_decrypt(caddr_t key, u_int8_t *blk)
{
    blf_ecb_decrypt((blf_ctx *) key, blk, 8);
}

void
blf_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, sizeof(blf_ctx), M_XDATA, M_WAITOK);
    bzero(*sched, sizeof(blf_ctx));
    blf_key((blf_ctx *)*sched, key, len);
}

void
blf_zerokey(u_int8_t **sched)
{
    bzero(*sched, sizeof(blf_ctx));
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

void
cast5_encrypt(caddr_t key, u_int8_t *blk)
{
    cast_encrypt((cast_key *) key, blk, blk);
}

void
cast5_decrypt(caddr_t key, u_int8_t *blk)
{
    cast_decrypt((cast_key *) key, blk, blk);
}

void
cast5_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, sizeof(blf_ctx), M_XDATA, M_WAITOK);
    bzero(*sched, sizeof(blf_ctx));
    cast_setkey((cast_key *)*sched, key, len);
}

void
cast5_zerokey(u_int8_t **sched)
{
    bzero(*sched, sizeof(cast_key));
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

void
skipjack_encrypt(caddr_t key, u_int8_t *blk)
{
    skipjack_forwards(blk, blk, (u_int8_t **) key);
}

void
skipjack_decrypt(caddr_t key, u_int8_t *blk)
{
    skipjack_backwards(blk, blk, (u_int8_t **) key);
}

void
skipjack_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, 10 * sizeof(u_int8_t *), M_XDATA, M_WAITOK);
    bzero(*sched, 10 * sizeof(u_int8_t *));
    subkey_table_gen(key, (u_int8_t **) *sched);
}

void
skipjack_zerokey(u_int8_t **sched)
{
    int k;

    for (k = 0; k < 10; k++)
	if (((u_int8_t **)(*sched))[k])
	{
	    bzero(((u_int8_t **)(*sched))[k], 0x100);
	    FREE(((u_int8_t **)(*sched))[k], M_XDATA);
	}
    bzero(*sched, 10 * sizeof(u_int8_t *));
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

void
rijndael128_encrypt(caddr_t key, u_int8_t *blk)
{
    rijndael_encrypt((rijndael_ctx *) key, (u4byte *) blk, (u4byte *) blk);
}

void
rijndael128_decrypt(caddr_t key, u_int8_t *blk)
{
    rijndael_decrypt(((rijndael_ctx *) key) + 1, (u4byte *) blk,
                     (u4byte *) blk);
}

void
rijndael128_setkey(u_int8_t **sched, u_int8_t *key, int len)
{
    MALLOC(*sched, u_int8_t *, 2 * sizeof(rijndael_ctx), M_XDATA, M_WAITOK);
    bzero(*sched, 2 * sizeof(rijndael_ctx));
    rijndael_set_key((rijndael_ctx *) *sched, (u4byte *) key, len * 8, 1);
    rijndael_set_key(((rijndael_ctx *) *sched) + 1, (u4byte *) key, len * 8, 0);
}

void
rijndael128_zerokey(u_int8_t **sched)
{
    bzero(*sched, 2 * sizeof(rijndael_ctx));
    FREE(*sched, M_XDATA);
    *sched = NULL;
}

/*
 * And now for auth.
 */

int
RMD160Update_int(void *ctx, u_int8_t *buf, u_int16_t len)
{
    RMD160Update(ctx, buf, len);
    return 0;
}

int
MD5Update_int(void *ctx, u_int8_t *buf, u_int16_t len)
{
    MD5Update(ctx, buf, len);
    return 0;
}

int
SHA1Update_int(void *ctx, u_int8_t *buf, u_int16_t len)
{
    SHA1Update(ctx, buf, len);
    return 0;
}

