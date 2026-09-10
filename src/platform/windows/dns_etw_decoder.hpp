#pragma once

#include "neta/name_resolution.hpp"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace neta::platform::windows_dns {

inline NameResolutionQueryKind query_kind(std::uint32_t query_type) noexcept {
    if (query_type == 1U || query_type == 28U) return NameResolutionQueryKind::Forward; // A / AAAA
    if (query_type == 12U) return NameResolutionQueryKind::Reverse; // PTR
    return NameResolutionQueryKind::Unknown;
}

inline NetworkAddressFamily address_family(std::string_view value) noexcept {
    IN_ADDR v4{};
    const std::string text(value);
    if (InetPtonA(AF_INET, text.c_str(), &v4) == 1) return NetworkAddressFamily::IPv4;
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET6, text.c_str(), &v6) == 1) return NetworkAddressFamily::IPv6;
    return NetworkAddressFamily::Unknown;
}

inline std::string trim_token(std::string value) {
    auto removable = [](unsigned char ch) {
        return std::isspace(ch) != 0 || ch == ',' || ch == ';' || ch == '[' || ch == ']' ||
               ch == '(' || ch == ')' || ch == '"' || ch == '\'';
    };
    while (!value.empty() && removable(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && removable(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

inline std::vector<NameResolutionAddress> extract_addresses(const std::string& text) {
    std::vector<NameResolutionAddress> result;
    std::string token;
    const auto flush = [&]() mutable {
        if (token.empty()) return;
        auto candidate = trim_token(std::move(token));
        token.clear();
        if (candidate.empty()) return;
        // Accept common provider representations such as "A:1.2.3.4" while not
        // stripping the colons inside a real IPv6 literal.
        const auto last_equal = candidate.find_last_of('=');
        if (last_equal != std::string::npos && last_equal + 1U < candidate.size()) {
            candidate = trim_token(candidate.substr(last_equal + 1U));
        }
        const auto family = address_family(candidate);
        if (family == NetworkAddressFamily::Unknown) return;
        const auto duplicate = std::find_if(result.begin(), result.end(), [&](const auto& existing) {
            return existing.family == family && existing.address == candidate;
        });
        if (duplicate == result.end()) result.push_back(NameResolutionAddress{family, candidate});
    };

    for (char ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == ',' || ch == ';') {
            flush();
        } else {
            token.push_back(ch);
        }
    }
    flush();
    return result;
}

inline bool successful_status(std::optional<int> status) noexcept {
    return !status || *status == 0;
}

} // namespace neta::platform::windows_dns
