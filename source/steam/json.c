#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

// Renvoie un pointeur sur la valeur associée à "key", espaces sautés.
static const char *find_value(const char *json, const char *key)
{
    if (!json) return NULL;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p)
        return NULL;
    p += strlen(needle);
    while (isspace((unsigned char)*p))
        p++;
    if (*p != ':')
        return NULL;
    p++;
    while (isspace((unsigned char)*p))
        p++;
    return p;
}

bool json_get_string(const char *json, const char *key, char *out, size_t out_len)
{
    const char *p = find_value(json, key);
    if (!p || *p != '"' || out_len == 0)
        return false;
    p++;

    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            c = *p++;
            switch (c) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'u': // caractère Unicode : inutile pour les champs lus ici, remplacé par '?'
                for (int k = 0; k < 4 && *p; k++)
                    p++;
                c = '?';
                break;
            default: break; // \" \\ \/
            }
        }
        if (n + 1 >= out_len)
            return false;
        out[n++] = c;
    }
    out[n] = '\0';
    return *p == '"';
}

bool json_get_long(const char *json, const char *key, long *out)
{
    const char *p = find_value(json, key);
    if (!p)
        return false;
    if (*p == '"') // Steam renvoie parfois les nombres entre guillemets
        p++;
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p)
        return false;
    *out = v;
    return true;
}

bool json_get_double(const char *json, const char *key, double *out)
{
    const char *p = find_value(json, key);
    if (!p)
        return false;
    char *end;
    double v = strtod(p, &end);
    if (end == p)
        return false;
    *out = v;
    return true;
}
