#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    long status;     // code HTTP
    int eresult;     // en-tête x-eresult de Steam (-1 si absent)
    char *body;      // corps de la réponse, terminé par '\0' (à libérer avec net_response_free)
    size_t len;
} NetResponse;

bool net_init(void);
void net_exit(void);

// Vérifie que l'horloge de la console est plausible : une date fausse (ex. 2051)
// fait échouer toutes les connexions HTTPS, les certificats semblant expirés.
bool net_clock_ok(int *year);

// POST application/x-www-form-urlencoded. `form` doit déjà être encodé (voir net_escape).
bool net_post_form(const char *url, const char *form, NetResponse *out);
bool net_get(const char *url, NetResponse *out);
// headers : tableau de chaînes "Nom: valeur" terminé par NULL
bool net_get_with_headers(const char *url, const char *const *headers, NetResponse *out);
// Requête quelconque (ex. "PUT") avec un corps binaire
bool net_send(const char *method, const char *url, const void *body, size_t body_len,
              const char *const *headers, NetResponse *out);
void net_response_free(NetResponse *resp);

// Encode une valeur pour un formulaire. Résultat à libérer avec free().
char *net_escape(const char *value);

// A sequential download queue can retain its CDN connection between requests.
void *net_download_open(void);
void net_download_close(void *connection);
bool net_download_get(void *connection, const char *url, NetResponse *out);
