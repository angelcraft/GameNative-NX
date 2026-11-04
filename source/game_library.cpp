#include "game_library.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

struct Game {
    std::string app_id;
    std::string name;
};

std::string read_log(const std::string& path) {
    std::ifstream file(path);
    std::vector<std::string> tail;
    for (std::string line; std::getline(file, line);) {
        if (tail.size() == 8)
            tail.erase(tail.begin());
        tail.push_back(line);
    }
    std::string result;
    for (const auto& line : tail)
        result += line + "\n";
    return result;
}

void log_event(const std::string& path, const char* event) {
    struct stat info{};
    if (stat(path.c_str(), &info) == 0 && info.st_size >= 32768) {
        const std::string previous = path + ".previous";
        std::remove(previous.c_str());
        if (std::rename(path.c_str(), previous.c_str()) != 0)
            return;
    }
    FILE* file = std::fopen(path.c_str(), "a");
    if (!file)
        return;
    std::fprintf(file, "%lld %s\n", static_cast<long long>(std::time(nullptr)), event);
    std::fclose(file);
}

std::vector<Game> load_library(const std::string& folder) {
    std::vector<Game> games;
    DIR* dir = opendir(folder.c_str());
    if (!dir)
        return games;
    while (dirent* entry = readdir(dir)) {
        const std::string filename = entry->d_name;
        if (filename.size() < 17 || filename.compare(0, 12, "appmanifest_") != 0 ||
            filename.compare(filename.size() - 4, 4, ".acf") != 0)
            continue;
        const std::string id = filename.substr(12, filename.size() - 16);
        if (id.size() > 10 || id.front() == '0' ||
            id.find_first_not_of("0123456789") != std::string::npos)
            continue;

        const auto path = folder + "/" + filename;
        struct stat info{};
        if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_size > 65536)
            continue;
        std::ifstream file(path);
        std::string app_id, name;
        int depth = 0;
        for (std::string line; std::getline(file, line);) {
            const auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            if (line[start] == '{') { ++depth; continue; }
            if (line[start] == '}') { --depth; continue; }
            if (depth != 1 || line[start] != '"')
                continue;
            std::string key, value;
            std::istringstream fields(line);
            if (!(fields >> std::quoted(key) >> std::quoted(value)))
                continue;
            if (key == "appid") app_id = value;
            if (key == "name") name = value;
        }
        name.erase(std::remove_if(name.begin(), name.end(), [](unsigned char ch) {
            return ch < 32 || ch == 127;
        }), name.end());
        if (app_id == id && !name.empty())
            games.push_back({app_id, name});
    }
    closedir(dir);
    std::sort(games.begin(), games.end(), [](const Game& a, const Game& b) {
        return a.name == b.name ? a.app_id < b.app_id : a.name < b.name;
    });
    return games;
}

} // namespace

void run_game_library(PadState& pad, const char* root) {
    const std::string base(root);
    const std::string library = base + "/library";
    const std::string logs = base + "/logs";
    mkdir(library.c_str(), 0777);
    mkdir(logs.c_str(), 0777);
    const std::string session = logs + "/session-" + std::to_string(std::time(nullptr)) +
        "-" + std::to_string(armGetSystemTick() % 8) + ".log";

    // Keep the eight newest session logs, plus one rotated file per game.
    std::vector<std::string> sessions;
    if (DIR* dir = opendir(logs.c_str())) {
        while (dirent* entry = readdir(dir)) {
            const std::string name = entry->d_name;
            if (name.compare(0, 8, "session-") == 0 &&
                name.find_first_not_of("0123456789-.log", 8) == std::string::npos)
                sessions.push_back(name);
        }
        closedir(dir);
    }
    std::sort(sessions.begin(), sessions.end());
    while (sessions.size() >= 8) {
        std::remove((logs + "/" + sessions.front()).c_str());
        sessions.erase(sessions.begin());
    }
    log_event(session, "Library opened");
    auto games = load_library(library);
    log_event(session, games.empty() ? "No Steam manifests found" : "Steam manifests loaded");
    size_t selected = 0;
    bool details = false;
    bool show_logs = false;
    std::string status;
    std::string runtime = "Wine";
    std::string log_view;
    while (appletMainLoop()) {
        consoleClear();
        std::printf("GameNative NX | Steam\n\n");
        const Game* game = games.empty() ? nullptr : &games[selected];
        const std::string game_log = game ? logs + "/steam-" + game->app_id + ".log" : "";
        const std::string config = game ? library + "/" + game->app_id + ".runtime" : "";
        if (show_logs) {
            std::printf("%s\nB Back\n", log_view.c_str());
        } else if (details && game) {
            std::printf("%.64s | Steam App %s\n\nRuntime preference: %s\n",
                        game->name.c_str(), game->app_id.c_str(), runtime.c_str());
            std::printf("Download and Play require Steam sign-in and a Horizon runtime.\n\n");
            std::printf("A Switch runtime preference | Y Logs | B Back\n%s\n", status.c_str());
        } else {
            std::printf("Local library | Steam account connection pending\n\n");
            if (!game)
                std::printf("Copy Steam appmanifest_*.acf files into:\n%s\n", library.c_str());
            for (size_t i = selected / 10 * 10; i < games.size() && i < selected / 10 * 10 + 10; ++i)
                std::printf("%c %.60s [%s]\n", i == selected ? '>' : ' ',
                            games[i].name.c_str(), games[i].app_id.c_str());
            std::printf("\nUp/Down Browse | A Configure | X Reload | Y Logs | B Back\n");
        }
        consoleUpdate(nullptr);
        padUpdate(&pad);
        const u64 buttons = padGetButtonsDown(&pad);
        if (buttons & HidNpadButton_B) {
            if (show_logs) show_logs = false;
            else if (details) details = false;
            else break;
        } else if (!show_logs && (buttons & HidNpadButton_Y)) {
            log_view = "Session log\n" + read_log(session);
            if (details)
                log_view += "\nGame log\n" + read_log(game_log);
            show_logs = true;
        } else if (details && !show_logs && game && (buttons & HidNpadButton_A)) {
            const std::string next_runtime = runtime == "Wine" ? "Proton" : "Wine";
            std::ofstream output(config, std::ios::app);
            output << '\n' << next_runtime << '\n';
            output.close();
            if (output)
                runtime = next_runtime;
            status = output ? "Preference saved" : "Failed to save preference";
            log_event(game_log, status.c_str());
        } else if (!details && !show_logs) {
            if (buttons & HidNpadButton_X) {
                games = load_library(library);
                selected = 0;
                log_event(session, games.empty() ? "No Steam manifests found" : "Steam manifests reloaded");
            } else if (game && (buttons & HidNpadButton_A)) {
                details = true;
                status.clear();
                runtime = "Wine";
                std::ifstream preferences(config);
                for (std::string line; std::getline(preferences, line);) {
                    if (line == "Wine" || line == "Proton")
                        runtime = line;
                }
                log_event(game_log, "Game settings opened");
            } else if (selected > 0 && (buttons & HidNpadButton_AnyUp)) {
                --selected;
            } else if (selected + 1 < games.size() && (buttons & HidNpadButton_AnyDown)) {
                ++selected;
            }
        }
        svcSleepThread(16'000'000ULL);
    }
    log_event(session, "Library closed");
}
