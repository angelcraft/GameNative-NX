#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "json.h"
#include "log.h"
#include "net.h"
#include "steam_auth.h"

#define API "https://api.steampowered.com/IAuthenticationService/"
#define DATA_DIR "sdmc:/switch/savesync"
#define SESSION_PATH DATA_DIR "/session.txt"

#define PLATFORM_STEAM_CLIENT 1
#define ERESULT_OK 1
#define ERESULT_EXPIRED 27

// ------------------------------------------------------------------ JWT

static int b64url_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

// Lit le champ "sub" (SteamID64) dans la charge utile d'un JWT
static bool jwt_subject(const char *token, char *out, size_t out_len)
{
    const char *start = strchr(token, '.');
    if (!start)
        return false;
    start++;
    const char *end = strchr(start, '.');
    if (!end)
        return false;

    size_t n = end - start;
    char *payload = malloc(n + 1);
    if (!payload) return false;
    size_t len = 0;
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64url_value(start[i]);
        if (v < 0)
            continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            payload[len++] = (acc >> bits) & 0xFF;
        }
    }
    payload[len] = '\0';
    bool ok = json_get_string(payload, "sub", out, out_len);
    free(payload);
    return ok;
}

// ------------------------------------------------------------------ QR

bool steam_qr_begin(SteamQrLogin *login)
{
    char form[256];
    snprintf(form, sizeof(form), "device_friendly_name=GameNative-NX%%20(Nintendo%%20Switch)&platform_type=%d",
             PLATFORM_STEAM_CLIENT);

    NetResponse resp;
    bool ok = net_post_form(API "BeginAuthSessionViaQR/v1/", form, &resp) &&
              resp.status == 200 && resp.eresult == ERESULT_OK &&
              json_get_string(resp.body, "client_id", login->client_id, sizeof(login->client_id)) &&
              json_get_string(resp.body, "request_id", login->request_id, sizeof(login->request_id)) &&
              json_get_string(resp.body, "challenge_url", login->challenge_url, sizeof(login->challenge_url));
    long interval = 5;
    json_get_long(resp.body, "interval", &interval);
    login->interval = interval > 0 ? interval : 5;

    if (!ok)
        log_printf("BeginAuthSessionViaQR : HTTP %ld, eresult %d\n", resp.status, resp.eresult);
    net_response_free(&resp);
    return ok;
}

QrPollResult steam_qr_poll(SteamQrLogin *login, SteamSession *session)
{
    char *request_id = net_escape(login->request_id);
    if (!request_id) return QR_ERROR;
    char form[256];
    snprintf(form, sizeof(form), "client_id=%s&request_id=%s", login->client_id, request_id);
    free(request_id);

    NetResponse resp;
    if (!net_post_form(API "PollAuthSessionStatus/v1/", form, &resp)) {
        net_response_free(&resp);
        return QR_ERROR;
    }

    QrPollResult result = QR_PENDING;
    if (resp.eresult == ERESULT_EXPIRED) {
        result = QR_EXPIRED;
    } else if (resp.status != 200 || resp.eresult != ERESULT_OK) {
        log_printf("PollAuthSessionStatus : HTTP %ld, eresult %d\n", resp.status, resp.eresult);
        result = QR_ERROR;
    } else if (json_get_string(resp.body, "refresh_token", session->refresh_token,
                               sizeof(session->refresh_token))) {
        json_get_string(resp.body, "account_name", session->account_name, sizeof(session->account_name));
        result = jwt_subject(session->refresh_token, session->steamid, sizeof(session->steamid))
                     ? QR_DONE
                     : QR_ERROR;
    } else if (json_get_string(resp.body, "new_challenge_url", login->challenge_url,
                               sizeof(login->challenge_url))) {
        result = QR_NEW_URL;
    }

    net_response_free(&resp);
    return result;
}

