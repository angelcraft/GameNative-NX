#include <switch.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" {
#include "steam_auth.h"
#include "net.h"
#include "steam_cm.h"
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

static void show_steam_library(PadState& pad, const SteamSession& session) {
    consoleClear();
    std::puts("Connecting to Steam CM...");
    consoleUpdate(nullptr);

    std::vector<std::string> games;
    std::vector<uint32_t> appids;
    SteamCM cm{};
    const bool tls_ready = tls_init();
    bool loaded = false;
    if (tls_ready) {
        if (cm_connect(&cm)) {
            if (cm_logon(&cm, &session)) {
                log_printf("Steam CM logon accepted\n");
                PbBuf request{};
                pb_varint(&request, 1, cm.steamid);
                pb_varint(&request, 2, 1); // include_appinfo
                pb_varint(&request, 3, 1); // include_played_free_games
                pb_varint(&request, 5, 1); // include_free_sub
                uint8_t* response = nullptr;
                size_t length = 0;
                loaded = !request.error &&
                    cm_call(&cm, "Player.GetOwnedGames#1", &request, &response, &length) == 1;
                pb_free(&request);
                if (loaded) {
                    PbReader reader;
                    PbField field;
                    pb_reader(&reader, response, length);
                    while (pb_next(&reader, &field)) {
                        uint64_t id = 0;
                        if (field.field != 2 || field.wire != PB_BYTES ||
                            !pb_get_u64(field.data, field.len, 1, &id) || !id)
                            continue;
                        char name[256]{};
                        if (pb_get_string(field.data, field.len, 2, name, sizeof(name))) {
                            for (char* c = name; *c; ++c)
                                if (static_cast<unsigned char>(*c) < 32 || *c == 127) *c = ' ';
                        }
                        if (id > UINT32_MAX) continue;
                        appids.push_back(static_cast<uint32_t>(id));
                        games.push_back(std::to_string(id) + "  " + name);
                    }
                    log_printf("Steam library returned %zu entries\n", games.size());
                }
                std::free(response);
            }
        }
    }
    if (!loaded) log_printf("Steam library request failed\n");

    constexpr size_t page_size = 12;
    size_t selected = 0;
    char status[128]{};
    bool redraw = true;
    while (appletMainLoop()) {
        if (redraw) {
            consoleClear();
            if (loaded) {
                std::printf("Steam account library | %zu entries\n\n", games.size());
                const size_t start = selected / page_size * page_size;
                for (size_t i = start; i < games.size() && i < start + page_size; ++i)
                    std::printf("%c %.100s\n", i == selected ? '>' : ' ', games[i].c_str());
            } else {
                std::puts("Could not load Steam library. See logs/steam-auth.log.");
            }
            std::printf("\nUp/Down Select | Left/Right Page | A Check product info | B Back\n%s\n", status);
            consoleUpdate(nullptr);
            redraw = false;
        }
        padUpdate(&pad);
        const u64 buttons = padGetButtonsDown(&pad);
        if (buttons & HidNpadButton_B) break;
        if (loaded && !appids.empty()) {
            const size_t before = selected;
            if ((buttons & HidNpadButton_AnyDown) && selected + 1 < appids.size()) ++selected;
            if ((buttons & HidNpadButton_AnyUp) && selected > 0) --selected;
            if ((buttons & HidNpadButton_AnyRight) && selected + page_size < appids.size())
                selected += page_size;
            if ((buttons & HidNpadButton_AnyLeft) && selected >= page_size) selected -= page_size;
            if (selected != before) {
                status[0] = '\0';
                redraw = true;
            }
            if (buttons & HidNpadButton_A) {
                consoleClear();
                std::puts("Requesting Steam product metadata...");
                consoleUpdate(nullptr);
                size_t bytes = 0;
                const bool ok = cm_app_info_size(&cm, appids[selected], &bytes);
                if (ok)
                    std::snprintf(status, sizeof(status), "App %u: %zu metadata bytes received", appids[selected], bytes);
                else
                    std::snprintf(status, sizeof(status), "App %u: metadata unavailable", appids[selected]);
                log_printf("%s\n", status);
                redraw = true;
            }
        }
        svcSleepThread(16000000);
    }
    if (tls_ready) {
        cm_close(&cm);
        tls_exit();
    }
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
                if (state == QR_DONE) {
                    log_printf("Steam authorization received\n");
                    show_steam_library(pad, session);
                    break;
                }
            }
        }
        svcSleepThread(16000000);
    }
    std::memset(&login, 0, sizeof(login));
    net_exit();
    consoleClear();
}
