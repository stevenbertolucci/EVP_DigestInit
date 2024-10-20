// Author: Steven Bertolucci
// Course: CS370 - Introduction to Security
// Assignment: Project 1 - 3.8 Programming Project
// Due Date: 10/20/24
// -----------------------------------------------------------------------------------------
//  Citations:
//
//  The C code below for generate() function was copied from OpenSSL's documentation
//  which can be found here: https://docs.openssl.org/master/man3/EVP_Digest_hashInit/#examples
//
//  The link to this documentation was also provided via the Project's PDF document. 
// -----------------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <time.h>

#define RUNS 30

// See citations for more info
void EVP_Digest_hash(const EVP_MD *md, const char *message, unsigned char *hash_value) {
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL) {
       printf("Message digest create failed.\n");
       exit(1);
    }
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
        printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    if (!EVP_DigestUpdate(mdctx, message, strlen(message))) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    if (!EVP_DigestFinal_ex(mdctx, hash_value, &md_len)) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
}

// Generates a random string
// Citation for the following function: generate_random_string()
// Date: 10/17/2024
// Copied from and Adapted from:
// Source URL: https://medium.com/@tberkayayaz/generating-a-random-string-with-c-2b1337f339f7
void generate_random_string(char *str, size_t len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < len; i++) {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[len] = '\0';
}

// Weak collision resistance
void weak_collision(const EVP_MD *md) {
    char hash[EVP_MAX_MD_SIZE], random_hash[EVP_MAX_MD_SIZE], random_message[EVP_MAX_MD_SIZE];;
    char message[] = "This is a test message";
    int total_trials = 0;

    printf("Calculating weak collision resistance...\n");

    for (int i = 0; i < RUNS; i++) {
        int trials = 0;

        // Hash the fixed message
        EVP_Digest_hash(md, message, hash);

        // Brute-force to find a weak collision
        for (;;) {
            // Generate a random string
            generate_random_string(random_message, sizeof(random_message));

            // Hash the random message
            EVP_Digest_hash(md, random_message, random_hash);

            trials++;

            // Check if the first three bytes are the same
            if (memcmp(hash, random_hash, 3) == 0) {
                break;
            }
        };

        total_trials += trials;
    }

    // Calculate and display the average number of trials
    float average_trials = (float)total_trials / RUNS;
    printf("[Average number of trials over %d runs: %.2f]\n\n", RUNS, average_trials);
}

// Strong collision resistance
void strong_collision(const EVP_MD *md) {
    char hash1[EVP_MAX_MD_SIZE], hash2[EVP_MAX_MD_SIZE], mess1[EVP_MAX_MD_SIZE], mess2[EVP_MAX_MD_SIZE];
    int total_trials = 0;

    printf("Calculating strong collision resistance...\n");

    for (int i = 0; i < RUNS; i++) {
        int trials = 0;

        // Brute-force to find a strong collision
        for (;;) {
            // Generate two random strings
            generate_random_string(mess1, sizeof(mess1));
            generate_random_string(mess2, sizeof(mess2));

            // Ensure the messages are different
            if (strcmp(mess1, mess2) == 0) {
                continue;
            }

            // Hashing both messages
            EVP_Digest_hash(md, mess1, hash1);
            EVP_Digest_hash(md, mess2, hash2);

            trials++;

            // Check if first three bytes are same
            if (memcmp(hash1, hash2, 3) == 0) {
                break;
            }

        };

        total_trials += trials;
    }

    // Calculate and display the average number of trials
    float average_trials = (float)total_trials / RUNS;
    printf("[Average number of trials over %d runs: %.2f]\n\n", RUNS, average_trials);
}

int main(int argc, char *argv[])
{
    if (argv[1] == NULL) {
        printf("Usage: ./hash <digestname>\n");
        exit(1);
    }

    const EVP_MD *md = EVP_get_digestbyname(argv[1]);

    if (md == NULL) {
        printf("Unknown digest %s\n", argv[1]);
        exit(1);
    }

    printf("Calculating the average trials using %s. Please be patient. This may take up to 15 minutes...\n\n", argv[1]);

    srand(time(NULL));

    weak_collision(md);
    strong_collision(md);

    exit(0);
}