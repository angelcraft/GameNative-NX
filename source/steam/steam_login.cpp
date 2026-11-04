#include <switch.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ctime>

extern "C" {
#include "steam_auth.h"
#include "net.h"
#include "qrcodegen.h"
}

extern "C" void log_printf(const char* format, ...) {
    FILE* file = std::fopen("sdmc:/switch/gamenative_nx/logs/steam-auth.log", "a");
    if (!file) return;
    std::fprintf(file, "%lld ", static_cast<long long>(std::time(nullptr)));
    va_list args;
    va_start(args, format);
    std::vfprintf(file, format, args);
    va_end(args);
    std::fclose(file);
}

void run_steam_login(PadState& pad) {
    static SteamSession session{};
    SteamQrLogin login{};
    consoleClear();
    std::printf("Connecting to Steam...\n");
    consoleUpdate(nullptr);
    if (!net_init()) return;
    bool ready = steam_qr_begin(&login);
    QrPollResult state = ready ? QR_PENDING : QR_ERROR;
    u8 qr[qrcodegen_BUFFER_LEN_MAX], scratch[qrcodegen_BUFFER_LEN_MAX];
    bool redraw = true;
    u64 next_poll = armGetSystemTick();
    const u64 deadline = next_poll + armNsToTicks(180000000000ULL);
    while (appletMainLoop()) {
        if (redraw) {
            consoleClear();
            if (state == QR_DONE) {
                std::printf("Steam authorization received.\nAccount: %.63s\nSteam ID: %.23s\n\nLibrary synchronization pending.\nB Back\n", session.account_name, session.steamid);
            } else if (state == QR_ERROR || state == QR_EXPIRED) {
                std::printf("Steam authorization %s.\nCheck network, console date and logs/steam-auth.log.\nB Back\n",
                            state == QR_EXPIRED ? "expired" : "failed");
            } else if (qrcodegen_encodeText(login.challenge_url, scratch, qr, qrcodegen_Ecc_LOW,
                                           1, 5, qrcodegen_Mask_AUTO, true)) {
                int size = qrcodegen_getSize(qr);
                for (int y = -4; y < size + 4; ++y) {
                    std::printf("\x1b[%d;1H", y + 5);
                    for (int x = -4; x < size + 4; ++x)
                        std::printf(qrcodegen_getModule(qr, x, y) ? "\x1b[40m  " : "\x1b[47m  ");
                }
                std::printf("\x1b[0m\x1b[2;95HScan with Steam mobile app\x1b[4;95HB Back");
            } else {
                state = QR_ERROR;
                std::printf("Steam QR exceeds display capacity. B Back\n");
            }
            consoleUpdate(nullptr);
            redraw = false;
        }
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_B) break;
        if (state == QR_PENDING || state == QR_NEW_URL) {
            const u64 now = armGetSystemTick();
            if (now >= deadline) {
                state = QR_EXPIRED;
                redraw = true;
            } else if (now >= next_poll) {
                state = steam_qr_poll(&login, &session);
                redraw = state != QR_PENDING;
                const int interval = login.interval > 60 ? 60 : login.interval;
                next_poll = armGetSystemTick() + armNsToTicks(static_cast<u64>(interval) * 1000000000ULL);
                if (state == QR_DONE) log_printf("Steam authorization received\n");
            }
        }
        svcSleepThread(16000000);
    }
    std::memset(&login, 0, sizeof(login));
    net_exit();
    consoleClear();
}
