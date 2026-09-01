#pragma once

#ifdef _WIN32

#include <ctime>

inline std::tm* neta_windows_localtime_r(const std::time_t* value, std::tm* result) noexcept {
    return value != nullptr && result != nullptr && localtime_s(result, value) == 0 ? result : nullptr;
}

inline std::tm* neta_windows_gmtime_r(const std::time_t* value, std::tm* result) noexcept {
    return value != nullptr && result != nullptr && gmtime_s(result, value) == 0 ? result : nullptr;
}

#define localtime_r neta_windows_localtime_r
#define gmtime_r neta_windows_gmtime_r

#endif
