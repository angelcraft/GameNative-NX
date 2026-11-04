#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <curl/curl.h>
#include <switch.h>

#include "log.h"
#include "net.h"

#define USER_AGENT "SaveSync/0.1 (Nintendo Switch)"

bool net_init(void)
{
    // Les sockets sont initialisés par log_init() (nécessaires aussi pour nxlink)
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

bool net_clock_ok(int *year)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    *year = tm.tm_year + 1900;
    return *year >= 2025 && *year <= 2035;
}

void net_exit(void)
{
    curl_global_cleanup();
}

static size_t on_body(char *data, size_t size, size_t nmemb, void *user)
{
    NetResponse *resp = user;
    if (size && nmemb > (4 * 1024 * 1024) / size) return 0;
    size_t n = size * nmemb;
    if (n > 4 * 1024 * 1024 - resp->len) return 0;
    char *grown = realloc(resp->body, resp->len + n + 1);
    if (!grown)
        return 0;
    memcpy(grown + resp->len, data, n);
    resp->body = grown;
    resp->len += n;
    resp->body[resp->len] = '\0';
    return n;
}

static size_t on_header(char *data, size_t size, size_t nmemb, void *user)
{
    NetResponse *resp = user;
    size_t n = size * nmemb;
    static const char name[] = "x-eresult:";
    if (n > sizeof(name) && strncasecmp(data, name, sizeof(name) - 1) == 0)
        resp->eresult = atoi(data + sizeof(name) - 1);
    return n;
}

// method == NULL : GET, ou POST si body est fourni. body est envoyé tel quel (binaire possible).
// headers : tableau "Nom: valeur" terminé par NULL (optionnel).
static bool request(const char *method, const char *url, const void *body, size_t body_len,
                    const char *const *headers, NetResponse *out, CURL *connection)
{
    memset(out, 0, sizeof(*out));
    out->eresult = -1;

    CURL *curl = connection ? connection : curl_easy_init();
    if (!curl)
        return false;

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    }
    if (method)
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    struct curl_slist *list = NULL;
    for (int i = 0; headers && headers[i]; i++)
        list = curl_slist_append(list, headers[i]);
    if (list)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, out);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out->status);
    else
        log_printf("curl : %s\n", curl_easy_strerror(rc));
    if (connection) curl_easy_reset(curl);
    else curl_easy_cleanup(curl);
    curl_slist_free_all(list);

    if (!out->body)
        out->body = calloc(1, 1);
    return rc == CURLE_OK;
}

bool net_post_form(const char *url, const char *form, NetResponse *out)
{
    return request(NULL, url, form, strlen(form), NULL, out, NULL);
}

bool net_get(const char *url, NetResponse *out)
{
    return request(NULL, url, NULL, 0, NULL, out, NULL);
}

bool net_get_with_headers(const char *url, const char *const *headers, NetResponse *out)
{
    return request(NULL, url, NULL, 0, headers, out, NULL);
}

bool net_send(const char *method, const char *url, const void *body, size_t body_len,
              const char *const *headers, NetResponse *out)
{
    return request(method, url, body, body_len, headers, out, NULL);
}

void net_response_free(NetResponse *resp)
{
    free(resp->body);
    resp->body = NULL;
}

char *net_escape(const char *value)
{
    char *tmp = curl_easy_escape(NULL, value, 0);
    char *copy = tmp ? strdup(tmp) : NULL;
    curl_free(tmp);
    return copy;
}

void *net_download_open(void) { return curl_easy_init(); }
void net_download_close(void *connection) { if (connection) curl_easy_cleanup(connection); }
bool net_download_get(void *connection, const char *url, NetResponse *out)
{
    return request(NULL, url, NULL, 0, NULL, out, connection);
}
