#include "neta/windows_sensor_broker.hpp"
#include "sensor_broker_pipe.hpp"

#ifdef _WIN32

#include <cstdlib>
#include <stdexcept>
#include <string_view>

namespace neta::windows_sensor_broker {
namespace {

std::wstring utf8_to_wide(const std::string& text) {
    if (text.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) throw std::runtime_error("NETA_SENSOR_BROKER is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), required) <= 0) {
        throw std::runtime_error("NETA_SENSOR_BROKER is not valid UTF-8");
    }
    return result;
}

}  // namespace

bool broker_mode_requested() {
    const char* raw = std::getenv("NETA_SENSOR_MODE");
    if (raw == nullptr || *raw == '\0' || std::string_view(raw) == "native") return false;
    if (std::string_view(raw) == "broker") return true;
    throw std::runtime_error("NETA_SENSOR_MODE must be 'native' or 'broker'");
}

std::wstring configured_pipe_name() {
    const char* raw = std::getenv("NETA_SENSOR_BROKER");
    const std::string configured = raw != nullptr && *raw != '\0'
        ? std::string(raw)
        : std::string("neta-sensor-broker");
    return normalize_pipe_name(utf8_to_wide(configured));
}

std::string configured_endpoint_slot() {
    const char* raw = std::getenv("NETA_ENDPOINT_SLOT");
    if (raw == nullptr || *raw == '\0') {
        throw std::runtime_error("NETA_ENDPOINT_SLOT is required when NETA_SENSOR_MODE=broker");
    }
    return raw;
}

}  // namespace neta::windows_sensor_broker

#endif
