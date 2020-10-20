/*
 * Multiple-precision ("very long") integer arithmetic
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> based on original C++ software written by
 * George Barwood <george.barwood@dial.pipex.com>
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * References:
 *
 * 1.	Knuth, D. E.: "The Art of Computer Programming",
 *		2nd ed. (1981), vol. II (Seminumerical Algorithms), p. 257-258.
 *		Addison Wesley Publishing Company.
 *
 * 2.	Hansen, P. B.: "Multiple-length Division Revisited: a Tour of the Minefield".
 *		Software - Practice and Experience 24:6 (1994), 579-601.
 *
 * 3.	Menezes, A. J., van Oorschot, P. C., Vanstone, S. A.:
 *		"Handbook of Applied Cryptography", CRC Press (1997), section 14.2.5.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_param.h"
  #include "ec_vlong.h"
#else
  #include "crypt/ec_param.h"
  #include "crypt/ec_vlong.h"
#endif /* Compiler-specific includes */

#ifndef USE_BNLIB

void vlClear (vlPoint p)
{
	assert (p != NULL);
	memset (p, 0, sizeof (vlPoint));
} /* vlClear */


void vlCopy (vlPoint p, const vlPoint q)
	/* sets p := q */
{
	assert (p != NULL);
	assert (q != NULL);
	memcpy (p, q, (q[0] + 1) * sizeof (word16));
} /* vlCopy */


unsigned vlExtractLittleBytes (const vlPoint k, byte a[])
    /* dumps the contents of k into a[] in little-endian order; */
    /* evaluates to the number of bytes written to a[] */
{
	unsigned i, j, last;

	assert (k != NULL);
	if (k[0] == 0) {
		return 0;
	}
	for (i = 1, j = 0; i < k[0]; i++) {
		a[j++] = (byte) (k[i] & 0xFFU);
		a[j++] = (byte) ((k[i] >> 8) & 0xFFU);
	}
	i = k[0];
	a[j++] = (byte) (k[i] & 0xFFU);
	if ((last = (byte) ((k[i] >> 8) & 0xFFU)) != 0) {
		a[j++] = last;
	}
	return j;
} /* vlExtractLittleBytes */


int vlCompare (const vlPoint p, const vlPoint q)
	/* evaluates to -1 if p < q, +1 if p > q, and 0 if p == q */
{
	int i;

	assert (p != NULL);
	assert (q != NULL);
	if (p[0] > q[0]) return +1;
	if (p[0] < q[0]) return -1;
	for (i = p[0]; i > 0; i--) {
		if (p[i] > q[i]) return +1;
		if (p[i] < q[i]) return -1;
	}
	return 0;
} /* vlCompare */


int vlShortCompare (const vlPoint p, unsigned u)
	/* evaluates to -1 if p < (vlPoint)u, +1 if p > (vlPoint)u, and 0 if p == (vlPoint)u */
{
	assert (p != NULL);
	assert (u <= 0xFFFFU);
	if (p[0] > 1) {
		return +1;
	} else if (p[0] == 1) {
		return p[1] < u ? -1: p[1] > u ? +1 : 0;
	} else { /* p == 0 */
		return u == 0 ? 0 : -1;
	}
} /* vlShortCompare */


unsigned vlNumBits (const vlPoint k)
	/* evaluates to the number of bits of k (index of most significant bit, plus one) */
{
	unsigned i;
	word16 m, w;

	assert (k != NULL);
	if (k[0] == 0) {
		return 0;
	}
	w = k[k[0]]; /* last unit of k */
	for (i = (k[0] << 4), m = 0x8000U; m; i--, m >>= 1) {
		if (w & m) {
			return i;
		}
	}
	return 0;
} /* vlNumBits */


unsigned vlTakeBit (const vlPoint p, unsigned i)
	/* evaluates to the i-th bit of p */
{
	assert (p != NULL);
	if (i >= ((unsigned)p[0] << 4)) {
		/* no bit at index i (shouldn't this be an error?) */
		return 0;
	}
	return (p[(i >> 4) + 1] >> (i & 15)) & 1U;
} /* vlTakeBit */


unsigned vlLSWord (const vlPoint p)
	/* evaluates to the least significant 16-bit word of p */
{
	assert (p != NULL);
	return (unsigned) (p[0] ? p[1] : 0);
} /* vlLSWord */


void vlAdd (vlPoint u, const vlPoint v)
{
	word16 i;
	word32 t;

	assert (u != NULL);
	assert (v != NULL);
	/* clear high words of u if necessary: */
	for (i = u[0] + 1; i <= v[0]; i++) {
		u[i] = 0;
	}
    if (u[0] < v[0])
      u[0] = v[0];
	t = 0L;
	for (i = 1; i <= v[0]; i++) {
		t = t + (word32)u[i] + (word32)v[i];
		u[i] = (word16) (t & 0xFFFFUL);
		t >>= 16;
	}
    i = v[0]+1;
	while (t) {
        if ( i > u[0] )
        {
          u[i] = 0;
          u[0] += 1;
        }
        t = (word32)u[i] + 1;
		u[i] = (word16) (t & 0xFFFFUL);
        t >>= 16;
        i += 1;
	}
} /* vlAdd */


void vlShortAdd (vlPoint p, unsigned u)
	/* sets p := p + (vlPoint)u */
{
	word16 i;
	word32 t;

	assert (p != NULL);
	assert (u <= 0xFFFFU);
	t = (word32)u;
	for (i = 1; t; i++) {
		if (i > p[0]) {
			p[0]++;
			p[i] = 0;
		}
		t += (word32)p[i];
		p[i] = (word16)(t & 0xFFFFUL);
		t >>= 16;
	}
} /* vlShortAdd */


void vlSub (vlPoint p, const vlPoint q)
{
	/* assume p >= q */
	word32 carry = 0, tmp;
	word16 i;

	assert (p != NULL);
	assert (q != NULL);
	assert (vlCompare (p, q) >= 0);
	for (i = 1; i <= q[0]; i++) {
		tmp = 0x10000UL + (word32)p[i] - (word32)q[i] - carry;
		if (tmp >= 0x10000UL) {
			tmp -= 0x10000UL;
			carry = 0;
		} else {
			carry = 1;
		}
		p[i] = (word16) tmp;
	}
	/* i = q[0] + 1; */
	if (carry) {
		for (i = q[0] + 1; i <= p[0]; i++) {
			if (p[i]) {
				p[i]--;
				break;
			}
		}
	}
	while (p[0] && p[p[0]] == 0) {
		p[0]--;
	}
} /* vlSub */


void vlShortSub (vlPoint p, unsigned u)
{
	/* assume p >= u */
	word16 i;

	assert (p != NULL);
	assert (u <= 0xFFFFU);
	assert (vlShortCompare (p, u) >= 0);
	if (p[1] >= u) {
		p[1] -= u;
	} else {
		p[1] = (word16) (0x10000UL + (word32)p[1] - (word32)u);
		for (i = 2; i <= p[0]; i++) {
			if (p[i]) {
				p[i]--;
				break;
			}
		}
	}
	while (p[0] && p[p[0]] == 0) {
		p[0]--;
	}
} /* vlShortSub */


void vlShortLshift (vlPoint p, unsigned n)
{
	word16 i;

	assert (p != NULL);
	if (p[0] == 0) {
		return;
	}
	/* this will only work if 0 <= n <= 16 */
	if (p[p[0]] >> (16 - n)) {
		/* check if there is enough space for an extra unit: */
		if (p[0] <= (word16)(VL_UNITS + 1)) {
			++p[0];
			p[p[0]] = 0; /* just make room for one more unit */
		}
	}
	for (i = p[0]; i > 1; i--) {
		p[i] = (p[i] << n) | (p[i - 1] >> (16 - n));
	}
	p[1] <<= n;
} /* vlShortLshift */


void vlShortRshift (vlPoint p, unsigned n)
{
	word16 i;

	assert (p != NULL);
	if (p[0] == 0) {
		return;
	}
	/* this will only work if 0 <= n <= 16 */
	for (i = 1; i < p[0]; i++) {
		p[i] = (p[i + 1] << (16 - n)) | (p[i] >> n);
	}
	p[p[0]] >>= n;
	if (p[p[0]] == 0) {
		--p[0];
	}
} /* vlShortRshift */


void vlShortMultiply (vlPoint p, const vlPoint q, unsigned d)
	/* sets p = q * d, where d is a single digit */
{
	word16 i;
	word32 t;

	assert (p != NULL);
	assert (q != NULL);
	assert (q[0] <= (word16)VL_UNITS);
	if (d > 1) {
		t = 0L;
		for (i = 1; i <= q[0]; i++) {
			t += (word32)q[i] * (word32)d;
			p[i] = (word16) (t & 0xFFFFUL);
			t >>= 16;
		}
		if (t) {
			p[0] = q[0] + 1;
			p[p[0]] = (word16) (t & 0xFFFFUL);
		} else {
			p[0] = q[0];
		}
	} else if (d) { /* d == 1 */
		vlCopy (p, q);
	} else { /* d == 0 */
		p[0] = 0;
	}
} /* vlShortMultiply */


void vlRemainder (vlPoint u, const vlPoint v)
{
	vlPoint t;
	int shift = 0;

	assert (u != NULL);
	assert (v != NULL);
	assert (v[0] != 0);
	vlCopy( t, v );
	while ( vlCompare( u, t ) > 0 )
	{
		vlShortLshift( t, 1 );
		shift += 1;
	}
	while ( 1 )
	{
		if ( vlCompare( t, u ) > 0 )
		{
			if (shift)
			{
				vlShortRshift( t, 1 );
				shift -= 1;
			}
			else
				break;
		}
		else
			vlSub( u, t );
	}
} /* vlRemainder */


#if 0
/*********************************************************************/
/* >>> CAVEAT: THIS IS WORK IN PROGRESS; SKIP THIS WHOLE SECTION <<< */
/*********************************************************************/

void vlMod (vlPoint u, const vlPoint v)
	/* sets u := u mod v */
{
	int i; word16 ud, vd;
	word32 phat, qhat, v1, v2;
	static word16 d, U[2*VL_UNITS], V[VL_UNITS], t[VL_UNITS];

	if (v[0] == 1) {
		/* short division: divide u[1...u[0]] by v[1] */
		v1 = (word32)v[1]; v2 = 0L;
		for (i = u[0]; i > 0; i--) {
			v2 = ((v2 << 16) + (word32)u[i]) % v1;
		}
		u[0] = 1; u[1] = (word16)v2;
	} else if (u[0] >= v[0]) { /* nothing to do if u[0] < v[0] (u is already reduced mod v) */
		/* long division: */
		ud = u[0]; vd = v[0];
		/* normalize: */
		d = (word16) (0x10000UL / ((word32)v[vd] + 1L));
		vlShortMultiply (U, u, d); U[ud + 1] = 0;
		vlShortMultiply (V, v, d); V[vd + 1] = 0;
		v1 = (word32) V[vd];
		v2 = (word32) V[vd - 1];
		/* loop on i: */
		for (i = ud + 1; i > vd; i--) {
			/* calculate qhat as a trial quotient digit: */
			phat = ((word32) U[i] << 16) + (word32) U[i - 1];
			qhat = ((word32) U[i] == v1) ? 0xFFFFUL : phat / v1;
			while (v2 * qhat > ((phat - v1 * qhat) << 16) + (word32) U[i - 2]) {
				qhat--;
			}
			/* multiply, subtract, and check result: */
			vlSmallMultiply (t, V, (word16) qhat);
			if (t[0] < vd) {
				t[vd] = 0;
			}
			if (vlPartialSub (U + i - vd, t, vd + 1)) {
				qhat--;
				vlPartialAdd (U + i - vd, V, vd + 1);
			}
		}
		/* unnormalize to evaluate the remainder (divide U[1...vd] by d): */
		v1 = 0L; v2 = (word32)d;
		for (i = vd; i > 0; i--) {
			v1 = (v1 << 16) + (word32)U[i];
			u[i] = (word16) (v1 / v2);
			v1 %= v2;
		}
		u[0] = vd;
	}
} /* vlMod */
#endif /* OMIT */


void vlMulMod (vlPoint u, const vlPoint v, const vlPoint w, const vlPoint m)
{
	word16 i, j;
	vlPoint s, t;
	
	assert (u != NULL);
	assert (v != NULL);
	assert (w != NULL);
	assert (m != NULL);
	assert (m[0] != 0);
	vlClear (s);
	vlCopy (t, w);
	for (i = 1; i <= v[0]; i++) {
		word16 vi = v[i];
		for (j = 0; j < 16; j++) {
			if (vi & 1U) {
				vlAdd (s, t);
				vlRemainder (s, m);
			}
			vi >>= 1;
			vlShortLshift (t, 1);
			vlRemainder (t, m);
		}
	}
	vlCopy (u, s);
	vlClear (s);
	vlClear (t);
} /* vlMulMod */


void vlLoadOrder (vlPoint ord, const order_t prime_order)
{
	word16 i;

	for (i = 0; i <= prime_order[0]; i++) {
		ord[i] = prime_order[i];
	}
} /* vlLoadOrder */


#endif /* ?USE_BNLIB */


#ifdef SELF_TESTING


#ifdef USE_BNLIB
#include "bn.h"
#include "bnprint.h"
#endif /* ?USE_BNLIB */


void vlPrint (FILE *out, const char *tag, const vlPoint k)
	/* printf prefix tag and the contents of k to file out */
{
	vlPoint q;
	word16 i, t[VL_UNITS+2];

	assert (k != NULL);
	/* extract the significant words of k: */
	vlBegin (q);
	vlCopy (q, k);
	for (i = 0; vlShortCompare (q, 0) != 0; i++) {
		t[i] = vlLSWord (q);
		vlShortRshift (q, 16);
	}
	vlEnd (q);
	/* print k effectively: */
	fprintf (out, "%s", tag);
	if (i == 0) {
		/* i.e. k == 0 */
		fprintf (out, "0000");
	} else {
		while (i > 0) {
			fprintf (out, "%04x", t[--i]);
		}
	}
	fprintf (out, "\n");
} /* vlPrint */


void vlRandom (vlPoint k)
	/* sets k := <random very long integer value> */
{
	int i;

	assert (k != NULL);
	vlClear (k);
	for (i = 0; i < VL_UNITS; i++) {
		vlShortLshift (k, 16);
		vlShortAdd (k, (unsigned)rand());
	}
} /* vlRandom */


int vlSelfTest (int test_count)
{
	int i, tfail = 0, sfail = 0, afail = 0, rfail = 0;
	vlPoint m, p, q;
	clock_t elapsed;

	srand ((unsigned)(time(NULL) % 65521U));
	printf ("Executing %d vlong self tests...", test_count);
	vlBegin (m);
	vlBegin (p);
	vlBegin (q);
	elapsed = -clock ();
	for (i = 0; i < test_count; i++) {
		vlRandom (m);
		/* scalar triplication test: 3*m = m + m + m */
		vlShortMultiply (p, m, 3);
		vlClear (q); vlAdd (q, m); vlAdd (q, m); vlAdd (q, m);
		if (vlCompare (p, q) != 0) {
			tfail++;
			printf ("Triplication test #%d failed!\n", i);
			vlPrint (stdout, "m     ", m);
			vlPrint (stdout, "3*m   ", p);
			vlPrint (stdout, "m+m+m ", q);
		}
		/* shift test: (m << k) >> k = m */
		vlCopy (p, m);
		vlShortLshift (p, i%17);
		vlShortRshift (p, i%17);
		if (vlCompare (p, m) != 0) {
			sfail++;
			/* printf ("\nShift test #%d failed:\n", i%17); */
		}
		/* addition vs. shift test: m + m = m << 1 */
		vlCopy (p, m); vlAdd (p, p);
		vlCopy (q, m); vlShortLshift (q, 1);
		if (vlCompare (p, q) != 0) {
			afail++;
			/* printf ("Addition test #%d failed!\n", i); */
		}
		/* remainder test: m mod (m/2) == either 0 or 1 */
		vlCopy (p, m); vlCopy (q, m); vlShortRshift (q, 1);
		vlRemainder (p, q);
		if (vlShortCompare (p, 0) != 0 && vlShortCompare (p, 1) != 0) {
			rfail++;
			/* printf ("Remainder test #%d failed!\n", i); */
		}
	}
	elapsed += clock ();
	printf (" done, elapsed time = %.1f s.\n", (float)elapsed/CLOCKS_PER_SEC);
	if (tfail) printf ("---> %d triplications failed <---\n", tfail);
	if (sfail) printf ("---> %d shifts failed <---\n", sfail);
	if (afail) printf ("---> %d additions failed <---\n", afail);
	if (rfail) printf ("---> %d remainders failed <---\n", rfail);
	vlEnd (m);
	vlEnd (p);
	vlEnd (q);
	return tfail || sfail || afail || rfail;
} /* vlSelfTest */

#endif /* ?SELF_TESTING */
