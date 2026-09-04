#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace neta {
std::string sha256_hex(std::string_view input);
std::string sha256_file_hex(const std::filesystem::path& path);
}
