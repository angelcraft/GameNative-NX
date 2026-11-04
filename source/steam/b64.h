#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Taille du texte produit par b64_encode (sans le '\0' final)
#define B64_ENCODED_LEN(n) (((n) + 2) / 3 * 4)

// `out` doit faire au moins B64_ENCODED_LEN(len) + 1 octets.
void b64_encode(const uint8_t *in, size_t len, char *out);

// Décode `len` caractères. *out est alloué (à libérer). Refuse un texte invalide.
bool b64_decode(const char *in, size_t len, uint8_t **out, size_t *out_len);
