#pragma once

#ifdef _DEBUG

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[36m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define LOG(color, label, format, ...) \
    do { \
        printf("%s%s " ANSI_COLOR_RESET, color, label); \
        printf(format, ##__VA_ARGS__); \
        printf("\n"); \
    } while (0)


#define LINFO(...) LOG(ANSI_COLOR_BLUE, "[INFO]", __VA_ARGS__)
#define LWARNING(...) LOG(ANSI_COLOR_YELLOW, "[WARNING]", __VA_ARGS__)
#define LERROR(...) LOG(ANSI_COLOR_RED, "[ERROR]", __VA_ARGS__)
#define LOK(...) LOG(ANSI_COLOR_GREEN, "[OK]", __VA_ARGS__)
#define LTODO(...) LOG(ANSI_COLOR_MAGENTA, "[TODO]", __VA_ARGS__)
#define LLOG(...) LOG("\n", "", __VA_ARGS__)
#define LNEWLINE() LOG("\n")

#define LAST_ERROR_STR(...) "" // TODO: Implement

#else

#define LINFO(...)
#define LWARNING(...)
#define LERROR(...)
#define LOK(...)
#define LTODO(...)
#define LLOG(...)
#define LNEWLINE()

#define LAST_ERROR_STR(...)

#endif