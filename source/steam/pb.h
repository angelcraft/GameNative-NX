#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Protobuf minimal (sans .proto compilés), même logique que tools/pb.py.

enum { PB_VARINT = 0, PB_FIXED64 = 1, PB_BYTES = 2, PB_FIXED32 = 5 };

// ------------------------------------------------------------------ écriture

typedef struct {
    uint8_t *data;
    size_t len, cap;
    bool error;  // allocation échouée : le contenu n'est plus fiable
} PbBuf;

void pb_free(PbBuf *b);
void pb_varint(PbBuf *b, int field, uint64_t value);
void pb_fixed64(PbBuf *b, int field, uint64_t value);
void pb_bytes(PbBuf *b, int field, const void *data, size_t len);
void pb_string(PbBuf *b, int field, const char *s);

// ------------------------------------------------------------------ lecture

typedef struct {
    int field, wire;
    uint64_t value;          // PB_VARINT, PB_FIXED64, PB_FIXED32
    const uint8_t *data;     // PB_BYTES
    size_t len;
} PbField;

typedef struct {
    const uint8_t *data;
    size_t len, pos;
} PbReader;

void pb_reader(PbReader *r, const void *data, size_t len);
// Champ suivant ; false à la fin du message ou s'il est mal formé.
bool pb_next(PbReader *r, PbField *f);

// Premier champ `field` du message (raccourcis)
bool pb_get_u64(const void *data, size_t len, int field, uint64_t *out);
bool pb_get_bytes(const void *data, size_t len, int field, const uint8_t **out, size_t *out_len);
bool pb_get_string(const void *data, size_t len, int field, char *out, size_t out_size);
