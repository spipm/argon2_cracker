/*
 * Argon2 password cracker
 * Modified from https://github.com/P-H-C/phc-winner-argon2/
 * 
 */

#define _GNU_SOURCE 1

#define MAX_PASS_LEN 128

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "argon2.h"
#include "core.h"

#define UNUSED_PARAMETER(x) (void)(x)

static void usage(const char *cmd) {
    printf("Usage:  %s [-h] [-w wordlist] [-e encoded_hash]\n", cmd);

    printf("Parameters:\n");
    printf("\t-w\t\tWordlist\n");
    printf("\t-e\t\tEncoded hash (like $argon2id$v=19$m=4096,t=3,p=1$iu..)\n");

    printf("\t-h\t\tPrint %s usage\n", cmd);
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

int main(int argc, char *argv[]) {
    int opt, result = ARGON2_OK;

    argon2_type type = Argon2_id;
    size_t max_len = MAX_PASS_LEN;

    char *wordlist_file = NULL, *encoded_hash = NULL, *pwd = NULL;
    pwd = malloc(max_len+1);
    int pwdlen;


    /* parse args */
    while ((opt = getopt(argc, argv, "w:e:h")) != -1) {
        switch (opt) {

            case 'w':
                wordlist_file = optarg;
                break;

            case 'e':
                encoded_hash = optarg;
                break;
            
            case 'h':
                usage(argv[0]);
                return 1;
            case '?':
                usage(argv[0]);
                return 1;
        }
    }

    /* open wordlist */
    FILE *file = fopen(wordlist_file, "r");
    if (file == NULL)
        fatal("Error opening the file");

    /* try each word */
    while ((pwdlen = getline((char**)&pwd, &max_len, file)) != -1) {

        result = argon2_verify(encoded_hash, pwd, pwdlen-1, type);

        if (result == ARGON2_OK) {
            printf("Password was: %s\n", pwd);
            break;
        }
    }

    return result;
}

