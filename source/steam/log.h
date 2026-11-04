#pragma once

// Écrit à l'écran (console) et, si lancé via `nxlink -s`, sur le terminal du PC.
void log_init(void);
void log_exit(void);
void log_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
