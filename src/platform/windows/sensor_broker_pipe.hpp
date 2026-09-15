#pragma once

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace neta::windows_sensor_broker {

std::wstring normalize_pipe_name(const std::wstring& configured);
HANDLE connect_named_pipe_client(const std::wstring& pipe_name,
                                 std::chrono::milliseconds timeout);
bool write_pipe_message(HANDLE pipe, std::span<const std::byte> message);
std::optional<std::vector<std::byte>> read_pipe_message(HANDLE pipe,
                                                        std::chrono::milliseconds timeout);
void close_pipe(HANDLE& pipe) noexcept;

}  // namespace neta::windows_sensor_broker

#endif
