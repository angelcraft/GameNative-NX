#include <stdlib.h>
#include <string.h>

#include "pb.h"

// ------------------------------------------------------------------ écriture

void pb_free(PbBuf *b)
{
    free(b->data);
    memset(b, 0, sizeof(*b));
}

static void put(PbBuf *b, const void *data, size_t len)
{
    if (b->error)
        return;
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 64;
        while (cap < b->len + len)
            cap *= 2;
        uint8_t *grown = realloc(b->data, cap);
        if (!grown) {
            b->error = true;
            return;
        }
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void put_raw_varint(PbBuf *b, uint64_t v)
{
    uint8_t tmp[10];
    size_t n = 0;
    do {
        tmp[n] = v & 0x7F;
        v >>= 7;
        if (v)
            tmp[n] |= 0x80;
        n++;
    } while (v);
    put(b, tmp, n);
}

static void put_key(PbBuf *b, int field, int wire)
{
    put_raw_varint(b, (uint64_t)field << 3 | wire);
}

void pb_varint(PbBuf *b, int field, uint64_t value)
{
    put_key(b, field, PB_VARINT);
    put_raw_varint(b, value);
}

void pb_fixed64(PbBuf *b, int field, uint64_t value)
{
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++)
        tmp[i] = value >> (8 * i);
    put_key(b, field, PB_FIXED64);
    put(b, tmp, 8);
}

void pb_bytes(PbBuf *b, int field, const void *data, size_t len)
{
    put_key(b, field, PB_BYTES);
    put_raw_varint(b, len);
    put(b, data, len);
}

void pb_string(PbBuf *b, int field, const char *s)
{
    pb_bytes(b, field, s, strlen(s));
}

// ------------------------------------------------------------------ lecture

void pb_reader(PbReader *r, const void *data, size_t len)
{
    r->data = data;
    r->len = len;
    r->pos = 0;
}

static bool read_varint(PbReader *r, uint64_t *out)
{
    uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (r->pos >= r->len)
            return false;
        uint8_t byte = r->data[r->pos++];
        v |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) {
            *out = v;
            return true;
        }
    }
    return false;
}

static bool read_fixed(PbReader *r, int size, uint64_t *out)
{
    if (r->pos + size > r->len)
        return false;
    uint64_t v = 0;
    for (int i = 0; i < size; i++)
        v |= (uint64_t)r->data[r->pos + i] << (8 * i);
    r->pos += size;
    *out = v;
    return true;
}

bool pb_next(PbReader *r, PbField *f)
{
    uint64_t key;
    if (r->pos >= r->len || !read_varint(r, &key))
        return false;
    f->field = key >> 3;
    f->wire = key & 7;
    f->data = NULL;
    f->len = 0;
    f->value = 0;

    switch (f->wire) {
    case PB_VARINT:
        return read_varint(r, &f->value);
    case PB_FIXED64:
        return read_fixed(r, 8, &f->value);
    case PB_FIXED32:
        return read_fixed(r, 4, &f->value);
    case PB_BYTES: {
        uint64_t len;
        if (!read_varint(r, &len) || r->pos + len > r->len)
            return false;
        f->data = r->data + r->pos;
        f->len = len;
        r->pos += len;
        return true;
    }
    default:
        return false;
    }
}

static bool find(const void *data, size_t len, int field, PbField *f)
{
    PbReader r;
    pb_reader(&r, data, len);
    while (pb_next(&r, f))
        if (f->field == field)
            return true;
    return false;
}

bool pb_get_u64(const void *data, size_t len, int field, uint64_t *out)
{
    PbField f;
    if (!find(data, len, field, &f) || f.wire == PB_BYTES)
        return false;
    *out = f.value;
    return true;
}

bool pb_get_bytes(const void *data, size_t len, int field, const uint8_t **out, size_t *out_len)
{
    PbField f;
    if (!find(data, len, field, &f) || f.wire != PB_BYTES)
        return false;
    *out = f.data;
    *out_len = f.len;
    return true;
}

bool pb_get_string(const void *data, size_t len, int field, char *out, size_t out_size)
{
    const uint8_t *p;
    size_t n;
    if (!pb_get_bytes(data, len, field, &p, &n) || out_size == 0)
        return false;
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}
