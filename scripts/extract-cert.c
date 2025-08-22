/* Extract X.509 certificate in DER form from PEM.
 *
 * Simplified version compatible with OpenSSL 3.0+
 * Removes deprecated ENGINE API and PKCS#11 support.
 *
 * Original authors: David Howells, David Woodhouse
 * Modified by: ShirokoNeko
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static __attribute__((noreturn))
void format(void)
{
    fprintf(stderr, "Usage: scripts/extract-cert <source> <dest>\n");
    exit(2);
}

static void display_openssl_errors(int l)
{
    char buf[120];
    unsigned long e;

    if (ERR_peek_error() == 0)
        return;
    fprintf(stderr, "At extract-cert.c:%d:\n", l);

    while ((e = ERR_get_error())) {
        ERR_error_string(e, buf);
        fprintf(stderr, "- SSL %s\n", buf);
    }
}

#define ERR(cond, fmt, ...)             \
    do {                        \
        bool __cond = (cond);           \
        display_openssl_errors(__LINE__);   \
        if (__cond) {               \
            err(1, fmt, ## __VA_ARGS__);    \
        }                   \
    } while(0)

static BIO *wb;
static char *cert_dst;
int kbuild_verbose;

static void write_cert(X509 *x509)
{
    char buf[200];

    if (!wb) {
        wb = BIO_new_file(cert_dst, "wb");
        ERR(!wb, "%s", cert_dst);
    }
    X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
    ERR(!i2d_X509_bio(wb, x509), "%s", cert_dst);
    if (kbuild_verbose)
        fprintf(stderr, "Extracted cert: %s\n", buf);
}

int main(int argc, char **argv)
{
    char *cert_src;
    BIO *b;
    X509 *x509;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ERR_clear_error();

    kbuild_verbose = atoi(getenv("KBUILD_VERBOSE") ?: "0");

    if (argc != 3)
        format();

    cert_src = argv[1];
    cert_dst = argv[2];

    if (!cert_src[0]) {
        FILE *f = fopen(cert_dst, "wb");
        ERR(!f, "%s", cert_dst);
        fclose(f);
        exit(0);
    }

    b = BIO_new_file(cert_src, "rb");
    ERR(!b, "%s", cert_src);

    while ((x509 = PEM_read_bio_X509(b, NULL, NULL, NULL))) {
        write_cert(x509);
        X509_free(x509);
    }

    BIO_free(b);
    BIO_free(wb);

    return 0;
}
