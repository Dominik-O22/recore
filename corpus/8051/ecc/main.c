/* Makes two key pairs, agrees on a secret, and signs and verifies a hash. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "uECC.h"

/* No random source here: a counter stands in for one. */
static int count_up(uint8_t *dest, unsigned size)
{
    static uint8_t next = 1;
    while (size--)
        *dest++ = next += 37;
    return 1;
}

static uint8_t private1[32], private2[32], public1[64], public2[64], compressed[33];
static uint8_t secret1[32], secret2[32], hash[32], signature[64];

static void check(uECC_Curve curve)
{
    uECC_make_key(public1, private1, curve);
    uECC_make_key(public2, private2, curve);
    uECC_shared_secret(public2, private1, secret1, curve);
    uECC_shared_secret(public1, private2, secret2, curve);
    uECC_compress(public1, compressed, curve);
    uECC_decompress(compressed, public2, curve);
    memcpy(hash, public1, sizeof hash);
    uECC_sign(private1, hash, sizeof hash, signature, curve);
    printf("%d %d %d %d\n", uECC_curve_public_key_size(curve), memcmp(secret1, secret2, sizeof secret1),
           uECC_valid_public_key(public2, curve), uECC_verify(public1, hash, sizeof hash, signature, curve));
}

void main(void)
{
    uECC_set_rng(count_up);
    check(uECC_secp160r1());
    check(uECC_secp256r1());
    check(uECC_secp256k1());
    for (;;)
        ;
}
