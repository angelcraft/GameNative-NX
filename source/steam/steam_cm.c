#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "log.h"
#include "net.h"
#include "steam_cm.h"

#define CM_LIST_URL "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&cmtype=websockets"
#define CM_MAX_TRIES 5
#define CM_WAIT_SEC 30

#define PROTO_MASK 0x80000000u
#define EMSG_MULTI 1
#define EMSG_SERVICE_METHOD_RESPONSE 147
#define EMSG_SERVICE_METHOD_CALL_FROM_CLIENT 151
#define EMSG_CLIENT_HEARTBEAT 703
#define EMSG_CLIENT_LOGON_RESPONSE 751
#define EMSG_CLIENT_LOGGED_OFF 757
#define EMSG_CLIENT_LOGON 5514

#define PROTOCOL_VERSION 65580
#define OS_TYPE_WINDOWS10 16

// Champs de CMsgProtoBufHeader
#define H_STEAMID 1
#define H_SESSIONID 2
#define H_JOBID_SOURCE 10
#define H_JOBID_TARGET 11
#define H_TARGET_JOB_NAME 12
#define H_ERESULT 13

// ------------------------------------------------------------------ connexion

static bool next_endpoint(const char **cursor, char *host, size_t host_len, int *port)
{
    const char *p = strstr(*cursor, "\"endpoint\":\"");
    if (!p)
        return false;
    p += strlen("\"endpoint\":\"");
    const char *end = strchr(p, '"');
    const char *colon = memchr(p, ':', end ? end - p : 0);
    if (!end || !colon || (size_t)(colon - p) >= host_len)
        return false;
    memcpy(host, p, colon - p);
    host[colon - p] = '\0';
    *port = atoi(colon + 1);
    *cursor = end;
    return true;
}

bool cm_connect(SteamCM *cm)
{
    memset(cm, 0, sizeof(*cm));
    cm->next_job = 1;
    cm->heartbeat_sec = 30;

    NetResponse resp;
    if (!net_get(CM_LIST_URL, &resp) || resp.status != 200) {
        log_printf("Liste des serveurs Steam indisponible (HTTP %ld)\n", resp.status);
        net_response_free(&resp);
        return false;
    }

    const char *cursor = resp.body;
    char host[128];
    int port;
    for (int i = 0; i < CM_MAX_TRIES && next_endpoint(&cursor, host, sizeof(host), &port); i++) {
        log_printf("Connexion a %s:%d...\n", host, port);
        if (ws_connect(&cm->ws, host, port, "/cmsocket/")) {
            cm->connected = true;
            break;
        }
    }
    net_response_free(&resp);
    return cm->connected;
}

void cm_close(SteamCM *cm)
{
    if (cm->connected)
        ws_close(&cm->ws);
    cm->connected = false;
}

// ------------------------------------------------------------------ envoi

static bool cm_send(SteamCM *cm, uint32_t emsg, const PbBuf *body, uint64_t job, const char *target)
{
    PbBuf header = {0};
    pb_fixed64(&header, H_STEAMID, cm->steamid);
    pb_varint(&header, H_SESSIONID, (uint64_t)(int64_t)cm->sessionid);
    if (job)
        pb_fixed64(&header, H_JOBID_SOURCE, job);
    if (target)
        pb_string(&header, H_TARGET_JOB_NAME, target);

    size_t body_len = body ? body->len : 0;
    size_t total = 8 + header.len + body_len;
    uint8_t *frame = malloc(total);
    bool ok = frame && !header.error && !(body && body->error);
    if (ok) {
        uint32_t words[2] = {emsg | PROTO_MASK, header.len};  // little-endian, comme la Switch
        memcpy(frame, words, 8);
        memcpy(frame + 8, header.data, header.len);
        if (body_len)
            memcpy(frame + 8 + header.len, body->data, body_len);
        ok = ws_send_binary(&cm->ws, frame, total);
    }
    free(frame);
    pb_free(&header);
    return ok;
}

static void keepalive(SteamCM *cm)
{
    if (time(NULL) - cm->last_heartbeat >= cm->heartbeat_sec / 2) {
        cm_send(cm, EMSG_CLIENT_HEARTBEAT, NULL, 0, NULL);
        cm->last_heartbeat = time(NULL);
    }
}

// ------------------------------------------------------------------ réception

// Ce qu'on attend : un message `emsg`, et pour les réponses de service le bon job
typedef struct {
    uint32_t emsg;
    uint64_t job;
    bool found;
    uint8_t *header, *body;
    size_t header_len, body_len;
    bool logged_off;
} CmWait;

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1);
    if (copy)
        memcpy(copy, p, n);
    return copy;
}

static void handle_message(CmWait *w, const uint8_t *msg, size_t len);

static void handle_multi(CmWait *w, const uint8_t *body, size_t len)
{
    uint64_t unzipped_size = 0;
    const uint8_t *payload;
    size_t payload_len;
    pb_get_u64(body, len, 1, &unzipped_size);
    if (!pb_get_bytes(body, len, 2, &payload, &payload_len))
        return;

    uint8_t *unzipped = NULL;
    if (unzipped_size) {
        // Contenu gzip : on décompresse d'un coup, la taille finale est connue
        unzipped = malloc(unzipped_size);
        z_stream zs = {0};
        zs.next_in = (Bytef *)payload;
        zs.avail_in = payload_len;
        zs.next_out = unzipped;
        zs.avail_out = unzipped_size;
        if (!unzipped || inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
            free(unzipped);
            return;
        }
        int rc = inflate(&zs, Z_FINISH);
        inflateEnd(&zs);
        if (rc != Z_STREAM_END) {
            log_printf("CM : message Multi corrompu\n");
            free(unzipped);
            return;
        }
        payload = unzipped;
        payload_len = unzipped_size;
    }

    for (size_t pos = 0; pos + 4 <= payload_len && !w->found;) {
        uint32_t n;
        memcpy(&n, payload + pos, 4);
        if (pos + 4 + n > payload_len)
            break;
        handle_message(w, payload + pos + 4, n);
        pos += 4 + n;
    }
    free(unzipped);
}

static void handle_message(CmWait *w, const uint8_t *msg, size_t len)
{
    if (len < 8)
        return;
    uint32_t raw_emsg, header_len;
    memcpy(&raw_emsg, msg, 4);
    memcpy(&header_len, msg + 4, 4);
    if (!(raw_emsg & PROTO_MASK) || 8 + (size_t)header_len > len)
        return;  // messages non-protobuf : rien d'utile pour nous

    uint32_t emsg = raw_emsg & ~PROTO_MASK;
    const uint8_t *header = msg + 8;
    const uint8_t *body = header + header_len;
    size_t body_len = len - 8 - header_len;

    if (emsg == EMSG_MULTI) {
        handle_multi(w, body, body_len);
        return;
    }
    if (emsg == EMSG_CLIENT_LOGGED_OFF) {
        w->logged_off = true;
        return;
    }
    if (emsg != w->emsg)
        return;
    if (w->job) {
        uint64_t target = 0;
        if (!pb_get_u64(header, header_len, H_JOBID_TARGET, &target) || target != w->job)
            return;
    }
    w->header = dup_bytes(header, header_len);
    w->header_len = header_len;
    w->body = dup_bytes(body, body_len);
    w->body_len = body_len;
    w->found = true;
}

static bool cm_wait(SteamCM *cm, CmWait *w)
{
    time_t deadline = time(NULL) + CM_WAIT_SEC;
    while (!w->found && !w->logged_off && time(NULL) < deadline) {
        uint8_t *frame;
        size_t len;
        if (!ws_recv(&cm->ws, &frame, &len))
            return false;
        handle_message(w, frame, len);
        free(frame);
    }
    if (w->logged_off)
        log_printf("CM : deconnecte par Steam\n");
    return w->found;
}

static void wait_free(CmWait *w)
{
    free(w->header);
    free(w->body);
}

static int32_t header_eresult(const CmWait *w)
{
    uint64_t v = 2;  // valeur par défaut du champ : k_EResultFail
    pb_get_u64(w->header, w->header_len, H_ERESULT, &v);
    return (int32_t)v;
}

// ------------------------------------------------------------------ logon

bool cm_logon(SteamCM *cm, const SteamSession *session)
{
    cm->steamid = strtoull(session->steamid, NULL, 10);

    char machine[64];
    snprintf(machine, sizeof(machine), "SaveSync (Nintendo Switch)");

    PbBuf body = {0};
    pb_varint(&body, 1, PROTOCOL_VERSION);              // protocol_version
    pb_string(&body, 6, "english");                     // client_language
    pb_varint(&body, 7, OS_TYPE_WINDOWS10);             // client_os_type
    pb_varint(&body, 8, 1);                             // should_remember_password
    pb_string(&body, 50, session->account_name);        // account_name
    pb_string(&body, 96, machine);                      // machine_name
    pb_string(&body, 108, session->refresh_token);      // access_token (= refresh token)
    bool sent = cm_send(cm, EMSG_CLIENT_LOGON, &body, 0, NULL);
    pb_free(&body);
    if (!sent)
        return false;

    CmWait w = {.emsg = EMSG_CLIENT_LOGON_RESPONSE};
    if (!cm_wait(cm, &w)) {
        wait_free(&w);
        return false;
    }

    uint64_t eresult = 2, heartbeat = 30, steamid = 0, sessionid = 0;
    pb_get_u64(w.body, w.body_len, 1, &eresult);
    pb_get_u64(w.body, w.body_len, 3, &heartbeat);
    pb_get_u64(w.header, w.header_len, H_STEAMID, &steamid);
    pb_get_u64(w.header, w.header_len, H_SESSIONID, &sessionid);
    wait_free(&w);

    if ((int32_t)eresult != 1) {
        log_printf("Logon refuse par Steam (eresult %d)\n", (int32_t)eresult);
        return false;
    }
    if (steamid)
        cm->steamid = steamid;
    cm->sessionid = (int32_t)sessionid;
    cm->heartbeat_sec = heartbeat > 0 ? (int)heartbeat : 30;
    cm->last_heartbeat = time(NULL);
    return true;
}

// ------------------------------------------------------------------ services

int cm_call(SteamCM *cm, const char *method, const PbBuf *body, uint8_t **resp, size_t *resp_len)
{
    keepalive(cm);
    uint64_t job = cm->next_job++;
    if (!cm_send(cm, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, body, job, method))
        return CM_TRANSPORT_ERROR;

    CmWait w = {.emsg = EMSG_SERVICE_METHOD_RESPONSE, .job = job};
    if (!cm_wait(cm, &w)) {
        wait_free(&w);
        log_printf("%s : pas de reponse\n", method);
        return CM_TRANSPORT_ERROR;
    }

    int32_t eresult = header_eresult(&w);
    if (eresult == 1) {
        *resp = w.body;
        *resp_len = w.body_len;
        w.body = NULL;
    } else {
        log_printf("%s : eresult %d\n", method, eresult);
    }
    wait_free(&w);
    return eresult;
}

bool cm_app_info(SteamCM *cm, uint32_t appid, uint8_t **data, size_t *size)
{
    // Steam PICS product info, one app per request.
    PbBuf app = {0}, request = {0};
    pb_varint(&app, 1, appid);
    pb_bytes(&request, 2, app.data, app.len);
    pb_varint(&request, 7, 1);
    uint64_t job = cm->next_job++;
    keepalive(cm);
    bool sent = !app.error && !request.error && cm_send(cm, 8903, &request, job, NULL);
    pb_free(&app);
    pb_free(&request);
    if (!sent)
        return false;

    CmWait response = {.emsg = 8904, .job = job};
    bool ok = false;
    if (cm_wait(cm, &response)) {
        PbReader reader;
        PbField field;
        pb_reader(&reader, response.body, response.body_len);
        while (pb_next(&reader, &field)) {
            uint64_t returned_id = 0;
            const uint8_t *metadata;
            if (field.field == 1 && field.wire == PB_BYTES &&
                pb_get_u64(field.data, field.len, 1, &returned_id) && returned_id == appid &&
                pb_get_bytes(field.data, field.len, 5, &metadata, size) && *size > 0) {
                *data = dup_bytes(metadata, *size);
                ok = *data != NULL;
                break;
            }
        }
    }
    wait_free(&response);
    return ok;
}
bool cm_depot_key(SteamCM *cm, uint32_t appid, uint32_t depot, uint8_t key[32])
{
    PbBuf request = {0};
    pb_varint(&request, 1, depot);
    pb_varint(&request, 2, appid);
    uint64_t job = cm->next_job++;
    keepalive(cm);
    bool sent = !request.error && cm_send(cm, 5438, &request, job, NULL);
    pb_free(&request);
    if (!sent) return false;

    CmWait reply = {.emsg = 5439, .job = job};
    uint64_t result = 0, returned_depot = 0;
    const uint8_t *bytes;
    size_t length;
    bool ok = cm_wait(cm, &reply) &&
        pb_get_u64(reply.body, reply.body_len, 1, &result) && result == 1 &&
        pb_get_u64(reply.body, reply.body_len, 2, &returned_depot) && returned_depot == depot &&
        pb_get_bytes(reply.body, reply.body_len, 3, &bytes, &length) && length == 32;
    if (ok) memcpy(key, bytes, 32);
    for (size_t i = 0; i < reply.body_len && reply.body; ++i)
        ((volatile uint8_t *)reply.body)[i] = 0;
    wait_free(&reply);
    log_printf("Depot %u key request result %llu\n", depot, (unsigned long long)result);
    return ok;
}
