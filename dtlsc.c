#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/prov_ssl.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>

#include <termios.h>

#include <openssl/ssl.h>

int main() {
    int r;

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *meth = DTLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);

    r = SSL_CTX_set_min_proto_version(ctx, DTLS1_VERSION);
    if (r != 1) {
        puts("PROTO ERR");
        exit(1);
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) err(1, "socket");

    struct sockaddr_in peer = {
        .sin_port = htons(8000),
        .sin_family = AF_INET
    };

    inet_aton("192.168.1.1", &peer.sin_addr);

    r = connect(s, (struct sockaddr *)&peer, sizeof(peer));
    if (r < 0) err(1, "connect");

    BIO *bio = BIO_new_dgram(s, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    puts("connecting...");

    r = SSL_connect(ssl);
    if (r != 1) {
        if (SSL_get_error(ssl, r) == SSL_ERROR_SYSCALL) {
            perror("connect");
        }
        puts("connect error");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    puts("connected");

    struct termios termios;
    struct termios raw_termios;
    r = tcgetattr(0, &termios);
    if (r < 0) err(1, "getattr");
    raw_termios = termios;
    cfmakeraw(&raw_termios);
    tcsetattr(0, TCSANOW, &raw_termios);

    char *errmsg = "-";
    while (1) {
        fd_set fds;
        char buf[256];

        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(s, &fds);

        r = select(s + 1, &fds, NULL, NULL, NULL);
        if (r < 0) { perror("select"); goto error; }

        if (FD_ISSET(0, &fds)) {
            r = read(0, buf, sizeof(buf));
            if (r < 0) { perror("read"); goto error; }
            SSL_write(ssl, buf, r);
        }
        if (FD_ISSET(s, &fds)) {
            r = SSL_read(ssl, buf, sizeof(buf));
            if (r <= 0) {
                if (SSL_get_error(ssl, r) == SSL_ERROR_SYSCALL) {
                    perror("ssl read");
                    goto error;
                }
                fprintf(stderr, "ssl error");
                ERR_print_errors_fp(stderr);
                goto error;
            }
            write(1, buf, r);
        }
    }

    error:
    tcsetattr(0, TCSANOW, &termios);
    puts("restored tty settings");

    return 0;
}