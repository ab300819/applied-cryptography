/*
 * Elliptic curve cryptographic primitives
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@nw.com.br> based on original C++ software written by
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
 */

#include <assert.h>

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "ec_curve.h"
  #include "ec_vlong.h"
  #include "ec_crypt.h"
#else
  #include "crypt/ec_curve.h"
  #include "crypt/ec_vlong.h"
  #include "crypt/ec_crypt.h"
#endif /* Compiler-specific includes */

extern const ecPoint curve_point;
extern const order_t prime_order;

void cpPairBegin (cpPair *pair)
{
	assert (pair != NULL);
	vlBegin (pair->r);
	vlBegin (pair->s);
} /* cpPairBegin */


void cpPairEnd (cpPair *pair)
{
	assert (pair != NULL);
	vlEnd (pair->r);
	vlEnd (pair->s);
} /* cpPairEnd */


void cpMakePublicKey (vlPoint vlPublicKey, const vlPoint vlPrivateKey)
{
	ecPoint ecPublicKey;

	ecCopy (&ecPublicKey, &curve_point);
	ecMultiply (&ecPublicKey, vlPrivateKey);
	ecPack (&ecPublicKey, vlPublicKey);
} /* cpMakePublicKey */


void cpEncodeSecret (const vlPoint vlPublicKey, vlPoint vlMessage, vlPoint vlSecret)
/*
	IN:
		vlSecret holds a one-time secret multiplier (k).
		vlPublicKey holds a partner's public key (x*P).
	OUT:
		vlMessage holds the secret multiplier's public form (k*P).
		vlSecret holds the shared value (k*x*P).
*/
{
	ecPoint q;

	ecCopy  (&q, &curve_point); ecMultiply (&q, vlSecret); ecPack (&q, vlMessage);
	ecUnpack (&q, vlPublicKey); ecMultiply (&q, vlSecret); gfPack (q.x, vlSecret);
} /* cpMakeSecret */


void cpDecodeSecret (const vlPoint vlPrivateKey, const vlPoint vlMessage, vlPoint vlShared)
/*
	IN:
		vlPrivateKey holds one's secret key (x).
		vlMessage holds the public form of a partner's secret multiplier (k*P).
	OUT:
		vlShared holds the shared value (x*k*P).
*/
{
	ecPoint q;

	ecUnpack (&q, vlMessage); ecMultiply (&q, vlPrivateKey); gfPack (q.x, vlShared);
} /* cpDecodeSecret */


void cpSign (const vlPoint vlPrivateKey, const vlPoint k, const vlPoint vlMac, cpPair *sig)
{
	ecPoint q;
	vlPoint tmp, ord;
				
	vlBegin (ord);
	vlLoadOrder (ord, prime_order);
	ecCopy (&q, &curve_point);
	ecMultiply (&q, k);
	gfPack(q.x, sig->r);
	vlAdd (sig->r, vlMac);
	vlRemainder (sig->r, ord);
	if (vlShortCompare (sig->r, 0) == 0) {
		return;
	}
	vlBegin (tmp);
	vlMulMod (tmp, vlPrivateKey, sig->r, ord);
	vlCopy (sig->s, k);
	if (vlCompare (tmp, sig->s) > 0) {
		vlAdd (sig->s, ord);
	}
	vlSub (sig->s, tmp);
	vlEnd (tmp);
	vlEnd (ord);
} /* cpSign */


int cpVerify (const vlPoint vlPublicKey, const vlPoint vlMac, cpPair *sig)
{
	int result;
	ecPoint t1,t2;
	vlPoint t3,t4, ord;

	vlBegin (t3);
	vlBegin (t4);
	vlBegin (ord);
	vlLoadOrder (ord, prime_order);
	ecCopy (&t1, &curve_point);
	ecMultiply (&t1, sig->s);
	ecUnpack (&t2, vlPublicKey);
	ecMultiply (&t2, sig->r);
	ecAdd (&t1, &t2);
	gfPack (t1.x, t4);
	vlRemainder (t4, ord);
	vlCopy (t3, sig->r);
	if (vlCompare( t4, t3 ) > 0) {
		vlAdd (t3, ord);
	}
	vlSub (t3, t4);
	result = vlCompare (t3, vlMac) == 0;
	vlEnd (ord);
	vlEnd (t4);
	vlEnd (t3);
	return result;
} /* cpVerify */
