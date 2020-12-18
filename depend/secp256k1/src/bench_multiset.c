/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "bench.h"


typedef struct {
    secp256k1_context *ctx;
} bench_multiset_data;


void bench_multiset_add(void* arg, int iters) {
    bench_multiset_data *data = (bench_multiset_data*)arg;
    int i;
    secp256k1_multiset multiset;
    unsigned char buf[100] = "multiset add element benchmark example string for 100 bytes this long message to 100 bytes abcdefghi";

    secp256k1_multiset_init(data->ctx, &multiset);

    for (i = 0; i < iters; i++) {
        buf[0] = i;
        buf[1] = i >> 8;
        buf[2] = i << 8;
        CHECK(secp256k1_multiset_add(data->ctx, &multiset, buf, sizeof(buf)));
    }
}

void bench_multiset_remove(void* arg, int iters) {
    bench_multiset_data *data = (bench_multiset_data*)arg;
    int i;
    secp256k1_multiset multiset;
    unsigned char buf[100] = "multiset add element benchmark example string for 100 bytes this long message to 100 bytes abcdefghi";

    secp256k1_multiset_init(data->ctx, &multiset);

    for (i = 0; i < iters; i++) {
        buf[99] = i;
        buf[98] = i >> 8;
        buf[97] = i << 8;
        CHECK(secp256k1_multiset_remove(data->ctx, &multiset, buf, sizeof(buf)));
    }
}

int main(void) {
    int iters = get_iters(10000);
    bench_multiset_data data;


    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    run_benchmark("multiset add", bench_multiset_add, NULL, NULL, &data, 30, iters*2);
    run_benchmark("multiset remove", bench_multiset_remove, NULL, NULL, &data, 30, iters*2);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
