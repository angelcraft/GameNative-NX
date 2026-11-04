#pragma once

#include <stdbool.h>

// Session Steam persistante : le refresh token permet de se reconnecter sans QR
// (validité ~200 jours). Stockée dans SESSION_PATH sur la carte SD.
typedef struct {
    char account_name[64];
    char steamid[24];
    char refresh_token[1024];
} SteamSession;

// Connexion en cours par QR code
typedef struct {
    char client_id[32];
    char request_id[64];
    char challenge_url[256];  // contenu du QR code
    int interval;             // secondes entre deux interrogations
} SteamQrLogin;

typedef enum {
    QR_PENDING,   // pas encore scanné / validé
    QR_NEW_URL,   // Steam a renouvelé le QR : réafficher challenge_url
    QR_DONE,      // connecté, session remplie
    QR_EXPIRED,   // session QR expirée : en recommencer une
    QR_ERROR,
} QrPollResult;

bool steam_qr_begin(SteamQrLogin *login);
QrPollResult steam_qr_poll(SteamQrLogin *login, SteamSession *session);

bool session_load(SteamSession *session);
bool session_save(const SteamSession *session);
void session_delete(void);
