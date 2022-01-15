#include<stdio.h>
#include<stdlib.h>

#include "bytes.h"
#include "bytes_impl.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

int main() {
    printf("Testing schnorrsig module of libsecp....\n");


    unsigned char sk[32];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk;
    const unsigned char msg[32] = "this is a msg for a schnorrsig..";
    unsigned char sig[64];

    /* create secp256k1 context */
    secp256k1_context *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* assign value to a seckey */
    unsigned char skval[] = "6368616E63656C6C6F72206F6E20746865206272696E6B206F66207365636F6E";
    /* secp256k1_testrand256(sk); */
    hex_str_to_buf(sk, 32, skval, 64);
    print_buf(sk,32);

    assert(secp256k1_keypair_create(ctx, &keypair, sk));
    assert(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));
    assert(secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL));

    print_buf(sk, 32);
    print_buf(pk.data, 64);
    print_buf(sig, 64);
    print_buf(msg, 32);

    return 0;
}