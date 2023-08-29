/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#define _GNU_SOURCE 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "argon2.h"
#include "core.h"

#include "blake2/blake2.h"
#include "blake2/blake2-impl.h"
#include "encoding.h"

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUTLEN_DEF 32
#define MAX_PASS_LEN 128



/* args for cracking thread */
typedef struct {
    argon2_type type;
    int thread_id;
    int n_cracking_threads;
    long file_size;
    char *wordlist_file;
    char *target_hash;
    char *encoded_hash;
    int *found;
    argon2_context a2_ctx;
} run_args;


/* helper functions */
static void usage(const char *cmd) {
    printf("Usage:  %s [-h] salt [-i|-d|-id] [-t iterations] "
           "[-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] "
           "[-l hash length] [-v (10|13)]\n",
           cmd);
    printf("Parameters:\n");
    printf("\t-w\t\tWordlist file\n");
    printf("\t-t\t\tTarget hash in hex\n");
    printf("\t-s\t\tTarget salt in hex\n");
    printf("\t-v\t\tUse Argon2 version (i for i, d for d, defaults to id)\n");
    printf("\t-i N\t\tSets the number of iterations to N (default = %d)\n",
           T_COST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n",
           LOG_M_COST_DEF);
    printf("\t-k N\t\tSets the memory usage of N KiB (default %d)\n",
           1 << LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N threads (default %d)\n",
           THREADS_DEF);
    printf("\t-t N\t\tSet number of threads to crack with\n");

    printf("\t-h\t\tPrint %s usage\n", cmd);
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

static void print_hex(uint8_t *bytes, size_t bytes_len) {
    size_t i;
    for (i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}



/* static part of original initialize function */
static argon2_instance_t argon2_ctx_custom_init(argon2_context *context, argon2_type type) {
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;

    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    instance.context_ptr = context;

    size_t size = sizeof(block);
    size_t num = instance.memory_blocks;
    uint8_t **memory = (uint8_t **)&instance.memory;
    size_t memory_size = num*size;

    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, memory_size);
    } else {
        *memory = malloc(memory_size);
    }

    return instance;
}

void finalize_custom(const argon2_context *context, argon2_instance_t *instance);


/* crack the hashes */
static void *run(void *args_p) {
    run_args *args = (run_args *)args_p;

    int *found = args->found;

    /* set argon2 context */
    argon2_context context;
    context = args->a2_ctx;

    /* open wordlist */
    FILE *file = fopen(args->wordlist_file, "r");
    if (file == NULL)
        fatal("Error opening the file");

    /* threads takes a chunk of the file */
    long thread_chunk_size = args->file_size / args->n_cracking_threads;
    long my_location = thread_chunk_size * args->thread_id;
    fseek(file, my_location, SEEK_CUR);
    long current_file_location = my_location;
    /*printf("Total chunk size = %ld\n", thread_chunk_size);printf("I'll start at %ld\n", my_location);*/


    /* here we go - Start with things that can be statically initialized */

    /* init argon2 instance */
    argon2_instance_t this_instance;
    uint8_t value[sizeof(uint32_t)];
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];

    /* this init is always the same */
    this_instance = argon2_ctx_custom_init(&context, args->type);

    /* pre-convert static values */
    uint8_t value_lanes[sizeof(uint32_t)];  store32(&value_lanes, context.lanes);
    uint8_t value_outlen[sizeof(uint32_t)]; store32(&value_outlen, context.outlen);
    uint8_t value_m_cost[sizeof(uint32_t)]; store32(&value_m_cost, context.m_cost);
    uint8_t value_t_cost[sizeof(uint32_t)]; store32(&value_t_cost, context.t_cost);
    uint8_t value_version[sizeof(uint32_t)];store32(&value_version, context.version);
    uint8_t value_type[sizeof(uint32_t)];   store32(&value_type, (uint32_t)args->type);
    uint8_t value_saltlen[sizeof(uint32_t)];store32(&value_saltlen, context.saltlen);
    uint8_t value_zero[sizeof(uint32_t)];   store32(&value_zero, 0);

    /* statically init blake2b params */
    blake2b_param P;
    P.digest_length = (uint8_t)ARGON2_PREHASH_DIGEST_LENGTH;
    P.key_length = 0;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    /* from core */
    static const uint64_t blake2b_IV[8] = {
        UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
        UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
        UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
        UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

    /* static init of blake hash */
    blake2b_state BlakeHash, static_state;
    blake2b_state *S, *S2;
    S = &BlakeHash;
    S2 = &static_state;
    /* init like original code */
    const blake2b_param *Pp = &P;
    const unsigned char *p = (const unsigned char *)Pp;
    unsigned int i;
    memset(S, 0, sizeof(*S));
    memcpy(S->h, blake2b_IV, sizeof(S->h));
    for (i = 0; i < 8; ++i) {
        S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
    }
    /* this only affects S->buf and S->buflen, for the values I tested, so we can pre-compute */
    blake2b_update(&BlakeHash, (const uint8_t *)&value_lanes, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)&value_outlen, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)&value_m_cost, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)&value_t_cost, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)&value_version, sizeof(value));
    blake2b_update(&BlakeHash, (const uint8_t *)&value_type, sizeof(value));
    /* save initialized state */
    memset(S2, 0, sizeof(*S2));
    memcpy(S2->h, S->h, sizeof(S->h));
    memcpy(S2->buf, S->buf, sizeof(S->buf));
    S2->buflen = S->buflen;

    /* read lines from wordlist */
    long count = 0;
    size_t max_len = MAX_PASS_LEN;
    while ((context.pwdlen = getline((char**)&context.pwd, &max_len, file)) != -1) {

        /* threading operations */
        count += 1;
        if (count % 1000 == 0) {
            printf("[T%i:%ld]\r", args->thread_id, count);
            fflush(stdout); 
            current_file_location = ftell(file);
            if (current_file_location > my_location + thread_chunk_size) {
                /*printf("Threat at end of chunk at %ld\n", current_file_location);*/
                break;
            }
        }
        if (*found == 1)
            break;

        /* remove newline */
        context.pwdlen -= 1;

        /* where the magic happens */

        /* restore static blake2b state */
        memset(S, 0, sizeof(*S));
        memcpy(S->h, S2->h, sizeof(S->h));
        memcpy(S->buf, S2->buf, sizeof(S->buf));
        S->outlen = Pp->digest_length;
        S->buflen = S2->buflen;

        /* from here on I don't think we can pre-compute */
        store32(&value, context.pwdlen);
        blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));
        blake2b_update(&BlakeHash, (const uint8_t *)context.pwd, context.pwdlen);

        /* static, but required because pwd changes the state */
        blake2b_update(&BlakeHash, (const uint8_t *)&value_saltlen, sizeof(value));
        /* we assume there is a salt */
        blake2b_update(&BlakeHash, (const uint8_t *)context.salt, context.saltlen);

        /* we don't use secret and ad in cracking */
        blake2b_update(&BlakeHash, (const uint8_t *)&value_zero, sizeof(value));
        blake2b_update(&BlakeHash, (const uint8_t *)&value_zero, sizeof(value));

        /* finalize hash */
        blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);

        /* initialize memory blocks */
        fill_first_blocks(blockhash, &this_instance);
        
        /* the bottle neck is in this fill_memory_blocks */
        fill_memory_blocks(&this_instance);

        /* compute final hash */
        finalize_custom(&context, &this_instance);
        

        /* don't even check for errors, just compare values */
        if (memcmp(context.out, args->target_hash+1, context.outlen) == 0) {
            printf("[!] PASSWORD FOUND by thread %i\n", args->thread_id);
            printf("\nPassword:\t%s", context.pwd);
            printf("For hash:\t%s\n", args->encoded_hash);

            *found = 1;
            break;
        }
    }

    fclose(file);
    free(context.out);
    
    return 0;
}



int main(int argc, char *argv[]) {

    /* required variables */
    long file_size;
    argon2_type type;
    int opt, n_cracking_threads;
    char *wordlist_file = NULL, *encoded_hash = NULL;

    /* default values */
    n_cracking_threads = 1;
    type = Argon2_id;

    /* parse args */
    while ((opt = getopt(argc, argv, "w:y:t:e:h")) != -1) {
        switch (opt) {

            case 'w':
                wordlist_file = optarg;
                break;

            case 'e':
                encoded_hash = optarg;
                break;

            case 't':
                n_cracking_threads = atoi(optarg);
                break;

            case 'y':
                if (strcmp(optarg, "i") == 0)
                    type = Argon2_i;
                else if (strcmp(optarg, "d") == 0)
                    type = Argon2_d;
                break;
            
            case 'h':
                usage(argv[0]);
                return 1;
            case '?':
                usage(argv[0]);
                return 1;
        }
    }

    /* init context for parsing hash */
    argon2_context ctx;

    /* no field can be longer than the encoded length */
    size_t encoded_len;
    encoded_len = strlen(encoded_hash);
    uint32_t max_field_len;
    max_field_len = (uint32_t)encoded_len;

    /* create buffers */
    ctx.saltlen = max_field_len;
    ctx.outlen = max_field_len;
    ctx.salt = malloc(ctx.saltlen);
    ctx.out = malloc(ctx.outlen);

    /* decode context */
    decode_string(&ctx, encoded_hash, type);

    /* let's print some info */
    printf("Type:\t\t%s\n", argon2_type2string(type, 1));
    printf("Iterations:\t%u\n", ctx.t_cost);
    printf("Memory:\t\t%u KiB\n", ctx.m_cost);
    printf("Parallelism:\t%u\n", ctx.lanes);
    printf("\n");
    printf("Wordlist file:\t%s\n", wordlist_file);
    printf("Target hash:\t"); print_hex(ctx.out, ctx.outlen);
    printf("Salt:\t\t"); print_hex(ctx.salt, ctx.saltlen);
    printf("\n");

    /* get file size */
    FILE *file = fopen(wordlist_file, "r");
    if (file == NULL)
        fatal("Error opening the file");
    fseek(file, 0L, SEEK_END);
    file_size = ftell(file);
    fclose(file);
    
    /* loop and spawn the threads */
    printf("Starting %d cracking threads\n", n_cracking_threads);
    pthread_t crack_threads[n_cracking_threads];
    run_args args[n_cracking_threads];

    int found = 0;
    int i; for (i=0; i<n_cracking_threads; ++i)
    {
        /* build thread args */
            /* build context */
        args[i].a2_ctx.saltlen = ctx.saltlen;
        args[i].a2_ctx.outlen = ctx.outlen;
        args[i].a2_ctx.m_cost = ctx.m_cost;
        args[i].a2_ctx.t_cost = ctx.t_cost;
        args[i].a2_ctx.lanes = ctx.lanes;
        args[i].a2_ctx.threads = ctx.threads;
        args[i].a2_ctx.version = ctx.version;
        args[i].a2_ctx.secret = NULL;
        args[i].a2_ctx.secretlen = 0;
        args[i].a2_ctx.ad = NULL;
        args[i].a2_ctx.adlen = 0;
        args[i].a2_ctx.allocate_cbk = NULL;
        args[i].a2_ctx.free_cbk = NULL;
        args[i].a2_ctx.flags = ARGON2_DEFAULT_FLAGS;
        args[i].a2_ctx.out = malloc(ctx.outlen);
        args[i].a2_ctx.pwd = malloc(ctx.outlen);
        args[i].target_hash = malloc(ctx.outlen);
        args[i].a2_ctx.salt = malloc(ctx.saltlen);
        memcpy(args[i].a2_ctx.out, ctx.out, ctx.outlen);
        memcpy(args[i].a2_ctx.salt, ctx.salt, ctx.saltlen);

            /* additional cracking parameters */
        memcpy(args[i].target_hash, ctx.out, ctx.outlen);
        args[i].type = type;
        args[i].thread_id = i;
        args[i].n_cracking_threads = n_cracking_threads;
        args[i].file_size = file_size;
        args[i].wordlist_file = wordlist_file;
        args[i].found = &found;
        args[i].encoded_hash = encoded_hash;

        /* let's a go */
        pthread_create(&crack_threads[i], NULL, run, (void *) &args[i]);

    }

    /* wait for threads to finish */
    for (i=0; i<n_cracking_threads; ++i) {
      pthread_join(crack_threads[i], NULL);
    }

    return 0;
}

