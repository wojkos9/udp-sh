#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cert.h"

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *clen) {
    *cookie = 'A';
    *clen = 1;
    return 1;
}

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int clen) {
    return 1;
}

int main() {
    int r;

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *meth = DTLSv1_server_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) err(1, "socket");

    struct sockaddr_in sin = {
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(8000),
        .sin_family = AF_INET
    };

    r = bind(s, (struct sockaddr *)&sin, sizeof(sin));
    if (r < 0) err(1, "bind");

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    BIO *crt_bio = BIO_new_mem_buf(s_crt, sizeof(s_crt));
    X509 *pem_crt = PEM_read_bio_X509(crt_bio, NULL, 0, NULL);
    if (pem_crt == 0) {
        puts("crt err");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO *key_bio = BIO_new_mem_buf(s_key, sizeof(s_key));
    EVP_PKEY *pem_key = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
    if (pem_key == 0) {
        puts("key err");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    r = SSL_CTX_use_certificate(ctx, pem_crt);
    r &= SSL_CTX_use_PrivateKey(ctx, pem_key);

    if (r == 0) {
        puts("error");
        ERR_print_errors_fp(stderr);
        exit(1);
    }


    BIO *bio = BIO_new_dgram(s, BIO_NOCLOSE);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    fprintf(stderr, "Listening on %s %hu\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    struct sockaddr_in peer = {};
    do {
        r = DTLSv1_listen(ssl, &peer);
        if (r < 0) {
            puts("error");
            ERR_print_errors_fp(stderr);
        }
    } while (r != 1);

    fprintf(stderr, "Connection received on %s %hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    r = connect(s, (struct sockaddr *)&peer, sizeof(peer));
    if (r < 0) err(1, "connect");

    do {
        r = SSL_accept(ssl);
    } while (r == 0);

    if (r == -1) {
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_SYSCALL) {
            perror("accept");
        }
        fprintf(stderr, "SSL_accept: %d\n", e);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    int ptm = posix_openpt(O_RDWR);
    if (ptm < 0) err(1, "openpt");

    r = unlockpt(ptm);
    if (r < 0) err(1, "unlock");

    if (fork() == 0) {
        char *ptn = ptsname(ptm);
        int pts = open(ptn, O_RDWR);
        printf("pts %s\n", ptn);
        if (pts < 0) err(1, "open pts");
        close(ptm);

        dup2(pts, 0);
        dup2(pts, 1);
        dup2(pts, 2);
        close(pts);

        setsid();

        ioctl(0, TIOCSCTTY, 1);

        system("sh");
        exit(1);
    }

    while(1) {
        fd_set fd;
        char buf[256];

        FD_ZERO(&fd);
        FD_SET(ptm, &fd);
        FD_SET(s, &fd);

        r = select(ptm + 1, &fd, NULL, NULL, NULL);
        if (r == -1) err(1, "select");
        if (FD_ISSET(ptm, &fd)) {
            r = read(ptm, buf, sizeof(buf));
            if (r == -1) err(1, "read");
            r = SSL_write(ssl, buf, r);
        }
        if (FD_ISSET(s, &fd)) {
            r = SSL_read(ssl, buf, sizeof(buf));
            if (r == 0) errx(1, "read ssl");
            r = write(ptm, buf, r);
        }
    }

    return 0;
}