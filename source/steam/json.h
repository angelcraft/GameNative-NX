#pragma once

#include <stdbool.h>
#include <stddef.h>

// Extraction minimale dans les petites réponses JSON de Steam (pas un parseur complet) :
// cherche la première occurrence de "key" et lit sa valeur.
bool json_get_string(const char *json, const char *key, char *out, size_t out_len);
bool json_get_long(const char *json, const char *key, long *out);
bool json_get_double(const char *json, const char *key, double *out);
