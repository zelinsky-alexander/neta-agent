#pragma once

#include <string>
#include <string_view>

namespace neta {
std::string sha256_hex(std::string_view input);
}
