#include <switch.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <cerrno>
#include "depot_manifest.h"

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

// PICS app buffers contain text KeyValues. Only inspect depots/<id>/manifests/public.
static size_t log_public_manifests(uint32_t appid, const uint8_t* data, size_t size,
                                   uint32_t& depot, uint64_t& manifest) {
    std::vector<std::string> path;
    std::string key;
    bool have_key = false;
    size_t count = 0;
    for (size_t i = 0; i < size && data[i];) {
        const char ch = static_cast<char>(data[i++]);
        if (ch == '/' && i < size && data[i] == '/') {
            while (i < size && data[i] != '\n') ++i;
        } else if (ch == '{' && have_key) {
            if (path.size() == 32) break;
            path.push_back(key);
            have_key = false;
        } else if (ch == '}' && !path.empty()) {
            path.pop_back();
            have_key = false;
        } else if (ch == '"') {
            std::string value;
            while (i < size && data[i] && data[i] != '"') {
                if (data[i] == '\\' && i + 1 < size) ++i;
                value += static_cast<char>(data[i++]);
            }
            if (i == size || data[i++] != '"') break;
            if (!have_key) {
                key = value;
                have_key = true;
                continue;
            }
            const auto decimal = [](const std::string& text) {
                return !text.empty() && text.size() <= 20 &&
                    text.find_first_not_of("0123456789") == std::string::npos;
            };
            if (path.size() == 5 && path[0] == "appinfo" && path[1] == "depots" &&
                decimal(path[2]) && path[3] == "manifests" && path[4] == "public" &&
                key == "gid" && decimal(value)) {
                log_printf("App %u depot %s public manifest %s\n", appid, path[2].c_str(), value.c_str());
                if (!depot) {
                    const auto id = std::strtoull(path[2].c_str(), nullptr, 10);
                    if (id <= UINT32_MAX) {
                        depot = static_cast<uint32_t>(id);
                        manifest = std::strtoull(value.c_str(), nullptr, 10);
                    }
                }
                ++count;
            }
            have_key = false;
        }
    }
    return count;
}

bool assemble_depot(uint32_t depot, uint64_t manifest, DepotPlan& plan,
                    const uint8_t key[32], const std::string& cache, PadState& pad);

// Ciphertext cache is deliberately separate from installed game files.
static bool download_depot_chunks(const std::string& host, uint32_t depot, uint64_t manifest, DepotPlan& plan, const uint8_t* key) {
    const std::string root = "sdmc:/switch/gamenative_nx/chunks";
    mkdir(root.c_str(), 0777);
    const std::string folder = root + "/" + std::to_string(depot);
    mkdir(folder.c_str(), 0777);
    PadState pad; padConfigureInput(1, HidNpadStyleSet_NpadStandard); padInitializeDefault(&pad);
    size_t downloaded = 0, cached = 0, failed = 0, verified = 0;
    unsigned consecutive_decode_failures = 0;
    void* connection = net_download_open();
    bool cancelled = false;
    for (size_t i = 0; i < plan.chunks.size(); ++i) {
        padUpdate(&pad);
        if (!appletMainLoop() || (padGetButtonsDown(&pad) & HidNpadButton_B)) { cancelled = true; break; }
        const auto& chunk = plan.chunks[i];
        const std::string path = folder + "/" + chunk.sha + ".encrypted";
        struct stat info{};
        const bool existing = stat(path.c_str(), &info) == 0 &&
            static_cast<uint64_t>(info.st_size) == chunk.compressed;
        if (existing && !key) { ++cached; continue; }
        std::vector<uint8_t> ciphertext, decoded;
        if (existing && key && chunk.compressed <= 4*1024*1024) {
            if (FILE* file = std::fopen(path.c_str(), "rb")) {
                ciphertext.resize(chunk.compressed);
                const bool read = std::fread(ciphertext.data(), 1, ciphertext.size(), file) == ciphertext.size();
                std::fclose(file);
                if (read && decode_depot_chunk(chunk, key, ciphertext.data(), ciphertext.size(), decoded)) {
                    ++cached;
                    ++verified;
                    continue;
                }
            }
        }
        consoleClear();
        std::printf("Downloading Steam depot %u\n%zu files | %zu unique chunks\nChunk %zu/%zu | cached %zu | downloaded %zu\nB Cancel (after current request)\n\nCaching Steam content; installation pending.\n", depot, plan.files, plan.chunks.size(), i+1, plan.chunks.size(), cached, downloaded);
        consoleUpdate(nullptr);
        const std::string url = "https://" + host + "/depot/" + std::to_string(depot) + "/chunk/" + chunk.sha;
        NetResponse response{};
        bool saved = false;
        if (net_download_get(connection, url.c_str(), &response) && response.status == 200 && response.len == chunk.compressed) {
            if (key && !decode_depot_chunk(chunk, key, response.body, response.len, decoded)) {
                log_printf("Depot %u chunk %zu: decrypt/decompress/integrity validation failed\n", depot, i+1);
                net_response_free(&response);
                ++failed;
                if (++consecutive_decode_failures >= 4) break;
                continue;
            }
            consecutive_decode_failures = 0;
            if (key) ++verified;
            const std::string temporary = path + ".tmp";
            if (FILE* file = std::fopen(temporary.c_str(), "wb")) {
                const bool written = std::fwrite(response.body, 1, response.len, file) == response.len;
                const bool closed = std::fclose(file) == 0;
                saved = written && closed && std::rename(temporary.c_str(), path.c_str()) == 0;
                if (!saved) std::remove(temporary.c_str());
            }
        }
        if (saved) ++downloaded; else ++failed;
        if (!saved || downloaded % 64 == 0)
            log_printf("Depot %u chunk %zu/%zu HTTP %ld bytes %zu/%u saved=%d\n", depot, i+1, plan.chunks.size(), response.status, response.len, chunk.compressed, saved);
        net_response_free(&response);
        if (!saved) break; // Retrying A resumes completed cache entries.
    }
    net_download_close(connection);
    log_printf("Depot %u cache: downloaded=%zu existing=%zu failed=%zu cancelled=%d verified=%zu\n", depot, downloaded, cached, failed, cancelled, verified);
    return key && !failed && !cancelled && verified == plan.chunks.size() &&
        assemble_depot(depot, manifest, plan, key, folder, pad);
}

static size_t fetch_manifest(SteamCM& cm, uint32_t appid, uint32_t depot, uint64_t manifest, uint64_t code, bool& assembled) {
    PbBuf query{};
    pb_varint(&query, 2, 20);
    uint8_t* response = nullptr;
    size_t length = 0;
    const int result = query.error ? CM_TRANSPORT_ERROR :
        cm_call(&cm, "ContentServerDirectory.GetServersForSteamPipe#1", &query, &response, &length);
    pb_free(&query);
    if (result != 1) return 0;

    PbReader reader;
    PbField field;
    pb_reader(&reader, response, length);
    const std::string folder = "sdmc:/switch/gamenative_nx/manifests";
    const std::string path = folder + "/" + std::to_string(depot) +
        "_" + std::to_string(manifest) + ".zip";
    DepotPlan plan;
    size_t usable = 0;
    struct stat info{};
    if (stat(path.c_str(), &info) == 0 && info.st_size > 0 && info.st_size <= 4*1024*1024) {
        if (FILE* file = std::fopen(path.c_str(), "rb")) {
            std::vector<uint8_t> cached(info.st_size);
            const bool read = std::fread(cached.data(), 1, cached.size(), file) == cached.size();
            std::fclose(file);
            if (read && read_depot_manifest(cached.data(), cached.size(), depot, manifest, plan))
                usable = cached.size();
        }
    }
    if (usable) log_printf("Depot %u reused validated manifest from SD (%zu bytes)\n", depot, usable);
    unsigned attempts = 0;
    while (attempts < 3 && pb_next(&reader, &field)) {
        if (field.field != 1 || field.wire != PB_BYTES) continue;
        char hostname[128]{};
        if (!pb_get_string(field.data, field.len, 9, hostname, sizeof(hostname)) &&
            !pb_get_string(field.data, field.len, 8, hostname, sizeof(hostname))) continue;
        const std::string host(hostname);
        const std::string suffix = ".steamcontent.com";
        if (host.size() <= suffix.size() ||
            host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0 ||
            host.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-") != std::string::npos)
            continue;
        ++attempts;

        if (!usable) {
            const std::string url = "https://" + host + "/depot/" + std::to_string(depot) +
                "/manifest/" + std::to_string(manifest) + "/5/" + std::to_string(code);
            NetResponse download{};
            if (net_get(url.c_str(), &download) && download.status == 200 &&
                read_depot_manifest(download.body, download.len, depot, manifest, plan)) {
                usable = download.len;
                mkdir(folder.c_str(), 0777);
                const std::string temporary = path + ".tmp";
                bool saved = false;
                if (FILE* file = std::fopen(temporary.c_str(), "wb")) {
                    const bool written = std::fwrite(download.body, 1, download.len, file) == download.len;
                    const bool closed = std::fclose(file) == 0;
                    saved = written && closed && std::rename(temporary.c_str(), path.c_str()) == 0;
                }
                if (!saved) {
                    log_printf("Depot %u manifest SD write failed (errno %d); using validated bytes in memory\n", depot, errno);
                    std::remove(temporary.c_str());
                }
            }
            log_printf("Depot %u manifest CDN HTTP %ld, received %zu bytes, usable %zu\n",
                       depot, download.status, download.len, usable);
            net_response_free(&download);
        }
        if (!usable) continue;
        uint8_t key[32]{};
        const bool has_key = cm_depot_key(&cm, appid, depot, key);
        assembled = download_depot_chunks(host, depot, manifest, plan, has_key ? key : nullptr);
        for (size_t i = 0; i < sizeof(key); ++i)
            static_cast<volatile uint8_t*>(key)[i] = 0;
        break;
    }
    if (!attempts) log_printf("No supported Steam manifest CDN found\n");
    std::free(response);
    return usable;
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
    if (tls_ready) cm_close(&cm);
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
            std::printf("\nUp/Down Select | Left/Right Page | A Download and assemble depot | B Back\n%s\n", status);
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
                uint8_t* metadata = nullptr;
                const bool ok = cm_connect(&cm) && cm_logon(&cm, &session) &&
                    cm_app_info(&cm, appids[selected], &metadata, &bytes);
                if (ok) {
                    uint32_t depot = 0;
                    uint64_t manifest = 0;
                    const uint32_t appid = appids[selected];
                    log_public_manifests(appid, metadata, bytes, depot, manifest);
                    size_t saved = 0;
                    bool assembled = false;
                    if (depot && manifest) {
                        PbBuf request{};
                        pb_varint(&request, 1, appid);
                        pb_varint(&request, 2, depot);
                        pb_varint(&request, 3, manifest);
                        pb_string(&request, 4, "public");
                        uint8_t* reply = nullptr;
                        size_t length = 0;
                        const int result = request.error ? CM_TRANSPORT_ERROR :
                            cm_call(&cm, "ContentServerDirectory.GetManifestRequestCode#1",
                                    &request, &reply, &length);
                        uint64_t code = 0;
                        const bool authorized = result == 1 && pb_get_u64(reply, length, 1, &code) && code;
                        log_printf("App %u depot %u manifest request code %s (result %d)\n",
                                   appid, depot, authorized ? "received" : "unavailable", result);
                        std::free(reply);
                        pb_free(&request);
                        if (authorized) saved = fetch_manifest(cm, appid, depot, manifest, code, assembled);
                    }
                    std::snprintf(status, sizeof(status), "App %u: manifest %zu bytes. %s", appids[selected], saved,
                                  assembled ? "Depot assembled on SD" : "Depot incomplete (see Steam log)");
                }
                else
                    std::snprintf(status, sizeof(status), "App %u: metadata unavailable", appids[selected]);
                cm_close(&cm);
                std::free(metadata);
                log_printf("%s\n", status);
                redraw = true;
            }
        }
        svcSleepThread(16000000);
    }
    if (tls_ready) tls_exit();
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
