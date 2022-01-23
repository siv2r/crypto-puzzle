#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>

#include "bytes.h"
#include "bytes_impl.h"
#include "field.h"
#include "field_impl.h"
#include "group.h"
#include "group_impl.h"
#include "hash.h"
#include "hash_impl.h"
#include "scalar.h"
#include "scalar_impl.h"

void bip340_challenge(secp256k1_scalar *out, const unsigned char *rx32,
                      const unsigned char *msg, int msglen,
                      unsigned char *pkx32) {
    unsigned char buf[32];
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    /* precompute sha256 midstate of
     * sha256(sha256("BIP0340/challenge")||sha256("BIP0340/challenge"))
     TODO: this midstate does not match when checked with hashlib library */
    sha.s[0] = 0x9cecba11ul;
    sha.s[1] = 0x23925381ul;
    sha.s[2] = 0x11679112ul;
    sha.s[3] = 0xd1627e0ful;
    sha.s[4] = 0x97c87550ul;
    sha.s[5] = 0x003cc765ul;
    sha.s[6] = 0x90f61164ul;
    sha.s[7] = 0x33e9b66aul;
    sha.bytes = 64;
    /* hash(r.x, pk.x, msg) */
    secp256k1_sha256_write(&sha, rx32, 32);
    secp256k1_sha256_write(&sha, pkx32, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(out, buf, NULL);
}

int main() {
    /* Initialize signatures and x co-ordinate of nonces */
    unsigned char s1_buf[32];
    unsigned char s2_buf[32];
    unsigned char r1x_buf[32];
    unsigned char r2x_buf[32];

    unsigned char s1_hex[] =
        "F801B1BF3D103771F74C5F70BB3A3557D87E5116294A9ABD357DC4367D123C9D";
    unsigned char s2_hex[] =
        "110C668DA0C408E4B5A8DBD021B56FE82A2A816962D19C2D7747ED32DCCA3396";
    unsigned char r1x_hex[] =
        "19D6493FBA397CDD1C1E10F9AB51E65531D587D7C53C04673779E1A307AC795C";
    unsigned char r2x_hex[] =
        "B0D1BB19E0FDC76FF9702EF847D486B39F78DFAF59A3AE5D88C6FE44A1E4ED46";
    hex_str_to_buf(s1_buf, 32, s1_hex, 64);
    hex_str_to_buf(s2_buf, 32, s2_hex, 64);
    hex_str_to_buf(r1x_buf, 32, r1x_hex, 64);
    hex_str_to_buf(r2x_buf, 32, r2x_hex, 64);

    /* set s1, s1 and :
       case 2: a = 1337, b = 31337 */
    secp256k1_scalar s1, s2, a, b;
    secp256k1_scalar_set_int(&a, 1337);
    secp256k1_scalar_set_int(&b, 31337);
    secp256k1_scalar_set_b32(&s1, s1_buf, NULL);
    secp256k1_scalar_set_b32(&s2, s2_buf, NULL);

    /* Initialize byte arrays of xonly pubkey, message and xonly nonce */
    unsigned char pkx_buf[32];
    unsigned char msg1_buf[32];
    unsigned char msg2_buf[32];
    unsigned char pkx_hex[] =
        "21922E7D5988A711123794D70B19C2827B1630BC2AB99887418D9EF4AFDB1AC2";
    unsigned char msg1_hex[] =
        "49276D20626574746572207769746820636F6465207468616E20776974682077";
    unsigned char msg2_hex[] =
        "4265696E67206F70656E20736F75726365206D65616E7320616E796F6E652063";

    hex_str_to_buf(pkx_buf, 32, pkx_hex, 64);
    hex_str_to_buf(msg1_buf, 32, msg1_hex, 64);
    hex_str_to_buf(msg2_buf, 32, msg2_hex, 64);

    /* calculate e1 and e2 */
    secp256k1_scalar e1, e2, sk;
    bip340_challenge(&e1, r1x_buf, msg1_buf, 32, pkx_buf);
    bip340_challenge(&e2, r2x_buf, msg2_buf, 32, pkx_buf);

    /* find the private key x = (s2-a*s1-b)*(e2-a*e1)^-1*/
    secp256k1_scalar_mul(&e1, &e1, &a);
    secp256k1_scalar_negate(&e1, &e1);
    assert(secp256k1_scalar_add(&e1, &e1, &e2) == 0);
    secp256k1_scalar_inverse_var(&e1, &e1);

    secp256k1_scalar_mul(&s1, &s1, &a);
    assert(secp256k1_scalar_add(&s1, &s1, &b) == 0);
    secp256k1_scalar_negate(&s1, &s1);
    assert(secp256k1_scalar_add(&s1, &s1, &s2) == 0);

    secp256k1_scalar_mul(&sk, &s1, &e1);

    /* print the seckey in hex and ascii format */
    unsigned char seckey[32];
    secp256k1_scalar_get_b32(seckey, &sk);
    print_hex(seckey, 32);
    print_ascii(seckey, 32);

    return 0;
}