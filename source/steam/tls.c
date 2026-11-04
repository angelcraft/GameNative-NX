#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "log.h"
#include "tls.h"

bool tls_init(void)
{
    // Le service est à compteur de références : sans effet si curl l'a déjà ouvert
    Result rc = sslInitialize(3);
    if (R_FAILED(rc))
        log_printf("sslInitialize : 0x%x\n", rc);
    return R_SUCCEEDED(rc);
}

void tls_exit(void)
{
    sslExit();
}

static int tcp_connect(const char *host, int port, int timeout_sec)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        log_printf("DNS : impossible de résoudre %s\n", host);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0) {
        // Les lectures TLS passent par cette socket : le timeout évite de bloquer indéfiniment
        struct timeval tv = {.tv_sec = timeout_sec};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            log_printf("TCP : connexion à %s:%d impossible\n", host, port);
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

bool tls_connect(TlsConn *t, const char *host, int port, int timeout_sec)
{
    memset(t, 0, sizeof(*t));
    t->tcp_fd = t->ssl_fd = -1;

    int fd = tcp_connect(host, port, timeout_sec);
    if (fd < 0)
        return false;

    Result rc = sslCreateContext(&t->ctx, SslVersion_Auto);
    if (R_FAILED(rc)) {
        log_printf("sslCreateContext : 0x%x\n", rc);
        close(fd);
        return false;
    }
    rc = sslContextCreateConnection(&t->ctx, &t->conn);
    if (R_FAILED(rc)) {
        log_printf("sslContextCreateConnection : 0x%x\n", rc);
        sslContextClose(&t->ctx);
        close(fd);
        return false;
    }

    // Le module SSL utilise la socket ; il peut en rendre une copie qu'il faudra fermer
    t->tcp_fd = fd;
    t->ssl_fd = socketSslConnectionSetSocketDescriptor(&t->conn, fd);
    t->open = true;

    rc = sslConnectionSetHostName(&t->conn, host, strlen(host));
    if (R_SUCCEEDED(rc))
        rc = sslConnectionSetVerifyOption(&t->conn, SslVerifyOption_PeerCa | SslVerifyOption_HostName |
                                                        SslVerifyOption_DateCheck);
    if (R_SUCCEEDED(rc))
        rc = sslConnectionDoHandshake(&t->conn, NULL, NULL, NULL, 0);
    if (R_FAILED(rc)) {
        log_printf("TLS : échec de la poignée de main avec %s (0x%x)\n", host, rc);
        tls_close(t);
        return false;
    }
    return true;
}

void tls_close(TlsConn *t)
{
    if (!t->open)
        return;
    if (t->ssl_fd >= 0)
        close(t->ssl_fd);
    sslConnectionClose(&t->conn);
    sslContextClose(&t->ctx);
    close(t->tcp_fd);
    t->open = false;
}

bool tls_write_all(TlsConn *t, const void *data, size_t len)
{
    const u8 *p = data;
    while (len > 0) {
        u32 written = 0;
        Result rc = sslConnectionWrite(&t->conn, p, len, &written);
        if (R_FAILED(rc) || written == 0) {
            log_printf("TLS : erreur d'écriture (0x%x)\n", rc);
            return false;
        }
        p += written;
        len -= written;
    }
    return true;
}

bool tls_read_exact(TlsConn *t, void *out, size_t len)
{
    u8 *dst = out;
    while (len > 0) {
        if (t->buf_pos == t->buf_len) {
            u32 got = 0;
            Result rc = sslConnectionRead(&t->conn, t->buf, sizeof(t->buf), &got);
            if (R_FAILED(rc) || got == 0) {
                log_printf("TLS : erreur de lecture (0x%x)\n", rc);
                return false;
            }
            t->buf_pos = 0;
            t->buf_len = got;
        }
        u32 n = t->buf_len - t->buf_pos;
        if (n > len)
            n = len;
        memcpy(dst, t->buf + t->buf_pos, n);
        t->buf_pos += n;
        dst += n;
        len -= n;
    }
    return true;
}
