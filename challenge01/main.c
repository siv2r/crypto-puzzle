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

void bip340_challenge(secp256k1_scalar *out, const unsigned char *rx32, const unsigned char *msg, int msglen, unsigned char *pkx32) {
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
    /* Q  : why not use secp256k1_fe instead of secp256k1_scalar?
     * Ans: can't do this since, _schnorrsig_challenge() function takes _scalar
     * inp type */

    /* Initialize signatures and x co-ordinate of nonce */
    secp256k1_scalar s1 =
        SECP256K1_SCALAR_CONST(0x32A1DB8D, 0x2669A00A, 0xFE7BE97A, 0xF8C355CC,
                               0xF2B49B99, 0x38B9E451, 0xA5C231A4, 0x5993D920);
    secp256k1_scalar s2 =
        SECP256K1_SCALAR_CONST(0x974240A9, 0xA9403996, 0xCA01A06A, 0x3BC8F0D7,
                               0xB71D87FB, 0x510E897F, 0xF3EC5BF3, 0x47E5C5C1);
    secp256k1_scalar rx =
        SECP256K1_SCALAR_CONST(0xF3F148DB, 0xF94B1BCA, 0xEE189630, 0x6141F319,
                               0x729DCCA9, 0x451617D4, 0xB529EB22, 0xC2FB521A);

    /* Initialize byte arrays of xonly pubkey, message and xonly nonce */
    unsigned char pkx_buf[32];
    unsigned char rx_buf[32];
    unsigned char msg1_buf[32];
    unsigned char msg2_buf[32];
    unsigned char pkx_hex[] =
        "463F9E1F3808CEDF5BB282427ECD1BFE8FC759BC6F65A42C90AA197EFC6F9F26";
    unsigned char msg1_hex[] =
        "6368616E63656C6C6F72206F6E20746865206272696E6B206F66207365636F6E";
    unsigned char msg2_hex[] =
        "6974206D69676874206D616B652073656E7365206A75737420746F2067657420";

    hex_str_to_buf(pkx_buf, 32, pkx_hex, 64);
    secp256k1_scalar_get_b32(rx_buf, &rx);
    hex_str_to_buf(msg1_buf, 32, msg1_hex, 64);
    hex_str_to_buf(msg2_buf, 32, msg2_hex, 64);

    /* calculate e1 and e2 */
    secp256k1_scalar e1, e2, sk;
    bip340_challenge(&e1, rx_buf, msg1_buf, 32, pkx_buf);
    bip340_challenge(&e2, rx_buf, msg2_buf, 32, pkx_buf);

    /* find the private key x = (s1-s2).(e1-e2)^-1*/
    secp256k1_scalar_negate(&e2, &e2);
    assert(secp256k1_scalar_add(&e1, &e1, &e2) == 0);
    secp256k1_scalar_inverse_var(&e1, &e1);

    secp256k1_scalar_negate(&s2, &s2);
    assert(secp256k1_scalar_add(&s1, &s1, &s2) == 0);

    secp256k1_scalar_mul(&sk, &s1, &e1);

    /* print the seckey in hex and ascii format */
    unsigned char seckey[32];
    secp256k1_scalar_get_b32(seckey, &sk);
    print_hex(seckey, 32);
    print_ascii(seckey, 32);

    return 0;
}

/*
TODO: why am I not getting an error if I don't define the -DSECP macro?
      *#else error is there in for checking this macro?
TODO: why there is an error if I put #include<secp256k1.h> at the bottom? */