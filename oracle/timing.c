/* Batch verification oracle adapter for the SQIsign reference implementation.
 * Reads lines: <id> <pk_hex> <msg_hex> <sig_hex>
 * Writes lines: <id> accept|reject
 * A blank sig_hex is written as "-" (empty signature).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sig.h>
#include <time.h>
#include "api.h"

static int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    if (strcmp(hex, "-") == 0) { *out = malloc(1); *outlen = 0; return 0; }
    size_t n = strlen(hex);
    if (n % 2) return -1;
    *outlen = n / 2;
    *out = malloc(*outlen ? *outlen : 1);
    if (!*out) return -1;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        (*out)[i] = (unsigned char)b;
    }
    return 0;
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) > 0) {
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (len == 0) continue;
        char *id = strtok(line, " \t");
        char *pkh = strtok(NULL, " \t");
        char *msgh = strtok(NULL, " \t");
        char *sigh = strtok(NULL, " \t");
        if (!id || !pkh || !msgh || !sigh) { printf("%s error_input\n", id ? id : "?"); continue; }
        unsigned char *pk = NULL, *msg = NULL, *sig = NULL;
        size_t pklen = 0, msglen = 0, siglen = 0;
        if (hex2bin(pkh, &pk, &pklen) || hex2bin(msgh, &msg, &msglen) || hex2bin(sigh, &sig, &siglen)) {
            printf("%s error_hex\n", id); free(pk); free(msg); free(sig); continue;
        }
        /* The reference API takes a fixed-size public key buffer; a wrong-sized
         * pk is out of contract, so report it rather than invoking UB. */
        if (pklen != CRYPTO_PUBLICKEYBYTES) {
            printf("%s pk_wrong_size(%zu!=%d)\n", id, pklen, CRYPTO_PUBLICKEYBYTES);
            free(pk); free(msg); free(sig); continue;
        }
        struct timespec t0, t1;
        int reps = 5, rc = 1;
        double best = 1e18;
        for (int r = 0; r < reps; r++) {
            clock_gettime(CLOCK_MONOTONIC, &t0);
            rc = sqisign_verify(msg, (unsigned long long)msglen, sig,
                                (unsigned long long)siglen, pk);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
            if (ns < best) best = ns;
        }
        double el_ns = best;
        { printf("%s %s %.1f\n", id, rc == 0 ? "accept" : "reject", el_ns); }
        fflush(stdout);
        free(pk); free(msg); free(sig);
    }
    free(line);
    return 0;
}
