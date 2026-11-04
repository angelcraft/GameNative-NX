#pragma once

#include "tls.h"

// Client WebSocket minimal (RFC 6455) au-dessus de TLS : messages binaires uniquement.
typedef struct {
    TlsConn tls;
} WsConn;

bool ws_connect(WsConn *ws, const char *host, int port, const char *path);
void ws_close(WsConn *ws);

bool ws_send_binary(WsConn *ws, const void *data, size_t len);

// Reçoit le prochain message complet (réassemble les fragments, répond aux pings).
// *out est alloué avec malloc et doit être libéré par l'appelant.
bool ws_recv(WsConn *ws, u8 **out, size_t *out_len);
