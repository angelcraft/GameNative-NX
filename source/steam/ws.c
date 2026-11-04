#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "log.h"
#include "ws.h"

#define WS_TIMEOUT_SEC 20
#define WS_MAX_MESSAGE (16 * 1024 * 1024)

enum { OP_CONTINUATION = 0, OP_TEXT = 1, OP_BINARY = 2, OP_CLOSE = 8, OP_PING = 9, OP_PONG = 10 };

bool ws_connect(WsConn *ws, const char *host, int port, const char *path)
{
    if (!tls_connect(&ws->tls, host, port, WS_TIMEOUT_SEC))
        return false;

    u8 nonce[16];
    char key[32];
    randomGet(nonce, sizeof(nonce));
    b64_encode(nonce, sizeof(nonce), key);

    char req[512];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "\r\n",
                     path, host, port, key);
    if (!tls_write_all(&ws->tls, req, n))
        goto fail;

    // Lit l'en-tête de réponse jusqu'à la ligne vide
    char resp[2048];
    size_t len = 0;
    while (len < sizeof(resp) - 1) {
        if (!tls_read_exact(&ws->tls, resp + len, 1))
            goto fail;
        len++;
        if (len >= 4 && memcmp(resp + len - 4, "\r\n\r\n", 4) == 0)
            break;
    }
    resp[len] = '\0';
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        log_printf("WebSocket refusé par %s : %.*s\n", host, (int)strcspn(resp, "\r\n"), resp);
        goto fail;
    }
    return true;

fail:
    tls_close(&ws->tls);
    return false;
}

void ws_close(WsConn *ws)
{
    tls_close(&ws->tls);
}

static bool send_frame(WsConn *ws, int opcode, const void *data, size_t len)
{
    // En-tête (max 14 octets) : FIN + opcode, longueur avec bit de masque, clé de masque
    u8 header[14];
    size_t h = 0;
    header[h++] = 0x80 | opcode;
    if (len < 126) {
        header[h++] = 0x80 | len;
    } else if (len <= 0xFFFF) {
        header[h++] = 0x80 | 126;
        header[h++] = len >> 8;
        header[h++] = len;
    } else {
        header[h++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--)
            header[h++] = (u64)len >> (8 * i);
    }
    u8 *mask = header + h;
    randomGet(mask, 4);
    h += 4;

    // Un client doit masquer tout ce qu'il envoie
    u8 *frame = malloc(h + len);
    if (!frame)
        return false;
    memcpy(frame, header, h);
    const u8 *src = data;
    for (size_t i = 0; i < len; i++)
        frame[h + i] = src[i] ^ mask[i & 3];
    bool ok = tls_write_all(&ws->tls, frame, h + len);
    free(frame);
    return ok;
}

bool ws_send_binary(WsConn *ws, const void *data, size_t len)
{
    return send_frame(ws, OP_BINARY, data, len);
}

bool ws_recv(WsConn *ws, u8 **out, size_t *out_len)
{
    u8 *msg = NULL;
    size_t msg_len = 0;

    for (;;) {
        u8 hdr[2];
        if (!tls_read_exact(&ws->tls, hdr, 2))
            goto fail;
        bool fin = hdr[0] & 0x80;
        int opcode = hdr[0] & 0x0F;
        bool masked = hdr[1] & 0x80;
        u64 len = hdr[1] & 0x7F;
        if (len == 126 || len == 127) {
            u8 ext[8];
            int n = len == 126 ? 2 : 8;
            if (!tls_read_exact(&ws->tls, ext, n))
                goto fail;
            len = 0;
            for (int i = 0; i < n; i++)
                len = len << 8 | ext[i];
        }
        u8 mask[4] = {0};
        if (masked && !tls_read_exact(&ws->tls, mask, 4))
            goto fail;
        if (msg_len + len > WS_MAX_MESSAGE) {
            log_printf("WebSocket : message trop gros (%llu o)\n", (unsigned long long)(msg_len + len));
            goto fail;
        }

        u8 *payload = malloc(len ? len : 1);
        if (!payload || !tls_read_exact(&ws->tls, payload, len)) {
            free(payload);
            goto fail;
        }
        if (masked)
            for (u64 i = 0; i < len; i++)
                payload[i] ^= mask[i & 3];

        if (opcode == OP_PING) {
            send_frame(ws, OP_PONG, payload, len);
            free(payload);
            continue;
        }
        if (opcode == OP_PONG) {
            free(payload);
            continue;
        }
        if (opcode == OP_CLOSE) {
            log_printf("WebSocket fermé par le serveur\n");
            free(payload);
            goto fail;
        }

        // Données : premier fragment ou suite d'un message fragmenté
        u8 *grown = realloc(msg, msg_len + len);
        if (!grown) {
            free(payload);
            goto fail;
        }
        msg = grown;
        memcpy(msg + msg_len, payload, len);
        msg_len += len;
        free(payload);

        if (fin) {
            *out = msg;
            *out_len = msg_len;
            return true;
        }
    }

fail:
    free(msg);
    return false;
}
