#include "neta/cli/observation_options.hpp"

#include <arpa/inet.h>
#include <netdb.h>

#include <limits>
#include <stdexcept>

namespace neta::cli {
namespace {

std::uint16_t parse_port(const std::string& value, const char* option) {
    const auto parsed = std::stoul(value);
    if (parsed == 0 || parsed > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error(std::string(option) + " requires a port in 1..65535");
    }
    return static_cast<std::uint16_t>(parsed);
}

ObservationTarget resolve_target_impl(const std::string& value) {
    if (value.empty()) throw std::runtime_error("--target host:port requires a value");
    ObservationTarget target;
    const auto separator = value.rfind(':');
    if (separator == std::string::npos) {
        target.host = value;
        target.port = 443;
    } else {
        target.host = value.substr(0, separator);
        target.port = parse_port(value.substr(separator + 1), "--target");
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses = nullptr;
    const auto service = std::to_string(target.port);
    const int result = ::getaddrinfo(target.host.c_str(), service.c_str(), &hints, &addresses);
    if (result != 0) {
        throw std::runtime_error("target resolution failed: " +
                                 std::string(::gai_strerror(result)));
    }
    for (auto* current = addresses; current; current = current->ai_next) {
        char buffer[INET6_ADDRSTRLEN]{};
        const void* address = nullptr;
        if (current->ai_family == AF_INET) {
            address = &reinterpret_cast<sockaddr_in*>(current->ai_addr)->sin_addr;
        } else if (current->ai_family == AF_INET6) {
            address = &reinterpret_cast<sockaddr_in6*>(current->ai_addr)->sin6_addr;
        }
        if (address && ::inet_ntop(current->ai_family, address, buffer, sizeof(buffer))) {
            target.addresses.insert(buffer);
        }
    }
    ::freeaddrinfo(addresses);
    return target;
}

std::string next_value(int argc, char** argv, int& index) {
    if (index + 1 >= argc) throw std::runtime_error(std::string(argv[index]) + " needs a value");
    ++index;
    return argv[index];
}

} // namespace

ObservationOptions parse_observation_options(int argc, char** argv, bool service_mode) {
    ObservationOptions options;
    int selected_modes = 0;
    std::optional<std::string> target_text;

    for (int index = 2; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--target") {
            target_text = next_value(argc, argv, index);
            options.mode = ObservationMode::Target;
            ++selected_modes;
        } else if (argument == "--outbound") {
            options.mode = ObservationMode::Outbound;
            ++selected_modes;
        } else if (argument == "--inbound") {
            options.mode = ObservationMode::Inbound;
            ++selected_modes;
        } else if (argument == "--all") {
            options.mode = ObservationMode::All;
            ++selected_modes;
        } else if (argument == "--local-port") {
            options.filter.local_port = parse_port(next_value(argc, argv, index), "--local-port");
        } else if (argument == "--remote-port") {
            options.filter.remote_port = parse_port(next_value(argc, argv, index), "--remote-port");
        } else if (argument == "--process") {
            options.filter.include_processes.insert(next_value(argc, argv, index));
        } else if (argument == "--exclude-process") {
            options.filter.exclude_processes.insert(next_value(argc, argv, index));
        } else if (argument == "--duration") {
            const auto seconds = std::stoll(next_value(argc, argv, index));
            if (seconds < 0) throw std::runtime_error("--duration must not be negative");
            options.duration = std::chrono::seconds(seconds);
        } else if (argument == "--poll-ms") {
            const auto milliseconds = std::stoll(next_value(argc, argv, index));
            if (milliseconds <= 0) throw std::runtime_error("--poll-ms must be positive");
            options.transport_interval = std::chrono::milliseconds(milliseconds);
        } else if (argument == "--maintenance-seconds") {
            const auto seconds = std::stoll(next_value(argc, argv, index));
            if (seconds <= 0) throw std::runtime_error("--maintenance-seconds must be positive");
            options.maintenance_interval = std::chrono::seconds(seconds);
        } else if (argument == "--db") {
            options.database = next_value(argc, argv, index);
        } else if (argument == "--ca") {
            options.ca_file = next_value(argc, argv, index);
        } else if (argument == "--max-db-mb") {
            options.max_database_bytes = std::stoull(next_value(argc, argv, index)) *
                                         1024ULL * 1024ULL;
        } else {
            throw std::runtime_error("unknown observation option: " + argument);
        }
    }

    if (selected_modes == 0 && service_mode) options.mode = ObservationMode::All;
    else if (selected_modes != 1) {
        throw std::runtime_error("select exactly one of --target, --outbound, --inbound, or --all");
    }
    if (target_text) options.target = resolve_target_impl(*target_text);
    if (!service_mode && !options.duration) options.duration = std::chrono::seconds(30);
    return options;
}

ObservationTarget resolve_observation_target(const std::string& value) {
    return resolve_target_impl(value);
}

} // namespace neta::cli
