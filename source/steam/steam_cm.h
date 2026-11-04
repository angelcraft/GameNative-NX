#pragma once

#include <time.h>

#include "pb.h"
#include "steam_auth.h"
#include "ws.h"

// Client minimal du protocole CM de Steam (celui du vrai client), même logique
// que tools/steamcm.py : WebSocket, logon avec le refresh token, appels de services.
typedef struct {
    WsConn ws;
    bool connected;
    uint64_t steamid;
    int32_t sessionid;
    uint64_t next_job;
    int heartbeat_sec;
    time_t last_heartbeat;
} SteamCM;

bool cm_connect(SteamCM *cm);
bool cm_logon(SteamCM *cm, const SteamSession *session);
void cm_close(SteamCM *cm);

#define CM_TRANSPORT_ERROR (-1)

// Appelle une méthode de service, ex. "Cloud.EnumerateUserFiles#1".
// Retourne l'eresult Steam (1 = OK) ou CM_TRANSPORT_ERROR. Si OK, *resp est alloué (à libérer).
int cm_call(SteamCM *cm, const char *method, const PbBuf *body, uint8_t **resp, size_t *resp_len);

bool cm_app_info(SteamCM *cm, uint32_t appid, uint8_t **data, size_t *size);
