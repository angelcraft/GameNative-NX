#include <stdlib.h>

#include "b64.h"

static const char TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void b64_encode(const uint8_t *in, size_t len, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = in[i] << 16 | (i + 1 < len ? in[i + 1] << 8 : 0) | (i + 2 < len ? in[i + 2] : 0);
        out[o++] = TABLE[(v >> 18) & 63];
        out[o++] = TABLE[(v >> 12) & 63];
        out[o++] = i + 1 < len ? TABLE[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? TABLE[v & 63] : '=';
    }
    out[o] = '\0';
}

static int value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool b64_decode(const char *in, size_t len, uint8_t **out, size_t *out_len)
{
    if (len % 4 != 0)
        return false;
    uint8_t *buf = malloc(len / 4 * 3 + 1);
    if (!buf)
        return false;

    size_t o = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v[4];
        for (int k = 0; k < 4; k++) {
            v[k] = in[i + k] == '=' ? 0 : value(in[i + k]);
            if (v[k] < 0 || (in[i + k] == '=' && i + 4 != len)) {
                free(buf);
                return false;
            }
        }
        uint32_t n = v[0] << 18 | v[1] << 12 | v[2] << 6 | v[3];
        buf[o++] = n >> 16;
        if (in[i + 2] != '=')
            buf[o++] = n >> 8;
        if (in[i + 3] != '=')
            buf[o++] = n;
    }
    *out = buf;
    *out_len = o;
    return true;
}
