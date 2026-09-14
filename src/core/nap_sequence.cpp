#include "neta/nap_sequence.hpp"

#include "neta/crypto.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

namespace neta {
namespace {

constexpr std::size_t kMaxLegacySequenceBytes = 64;
constexpr std::size_t kMaxSequenceRecordBytes = 256;
constexpr const char* kRecordHeader = "NETA-NAP-SEQUENCE/1\nsequence=";
constexpr const char* kChecksumPrefix = "\nchecksum=sha256:";

std::uint64_t parse_decimal(std::string text, const std::filesystem::path& path) {
    if (!text.empty() && text.back() == '\n') text.pop_back();
    if (!text.empty() && text.back() == '\r') text.pop_back();
    if (text.empty()) {
        throw std::runtime_error("NAP sequence state is malformed: empty value at " + path.string());
    }
    if (text.size() > kMaxLegacySequenceBytes) {
        throw std::runtime_error("NAP sequence state is malformed: value too large at " + path.string());
    }
    for (const unsigned char c : text) {
        if (c < '0' || c > '9') {
            throw std::runtime_error("NAP sequence state is malformed: non-decimal data at " + path.string());
        }
    }
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::runtime_error("NAP sequence state is malformed: invalid integer at " + path.string());
    }
    return value;
}

std::string make_record(std::uint64_t sequence) {
    const std::string body = std::string(kRecordHeader) + std::to_string(sequence) + '\n';
    return body + "checksum=sha256:" + sha256_hex(body) + '\n';
}

std::uint64_t parse_record(const std::string& text, const std::filesystem::path& path) {
    if (text.empty() || text.size() > kMaxSequenceRecordBytes) {
        throw std::runtime_error("NAP sequence record is malformed at " + path.string());
    }
    if (text.find('\0') != std::string::npos || !text.starts_with(kRecordHeader)) {
        throw std::runtime_error("NAP sequence record has invalid header at " + path.string());
    }
    const std::size_t digits_begin = std::char_traits<char>::length(kRecordHeader);
    const auto checksum_pos = text.find(kChecksumPrefix, digits_begin);
    if (checksum_pos == std::string::npos || checksum_pos == digits_begin) {
        throw std::runtime_error("NAP sequence record has invalid structure at " + path.string());
    }
    const auto digits = text.substr(digits_begin, checksum_pos - digits_begin);
    const auto sequence = parse_decimal(digits, path);
    if (text != make_record(sequence)) {
        throw std::runtime_error("NAP sequence record checksum or format mismatch at " + path.string());
    }
    return sequence;
}

struct SlotState {
    bool exists{false};
    bool valid{false};
    std::uint64_t value{0};
    std::string error;
};

#ifdef _WIN32
constexpr wchar_t kEventSourceName[] = L"NETAAgent";
constexpr wchar_t kEventSourceRegistryPath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\NETAAgent";
constexpr DWORD kEventSequenceRecovered = 1002;
constexpr DWORD kEventSequenceFailure = 1003;
constexpr auto kEventMinInterval = std::chrono::minutes(5);

std::mutex event_rate_mutex;
std::chrono::steady_clock::time_point last_recovery_event{};
std::chrono::steady_clock::time_point last_failure_event{};

std::wstring widen_utf8(const std::string& text) {
    if (text.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                             text.data(), static_cast<int>(text.size()),
                                             nullptr, 0);
    if (required <= 0) return std::wstring(text.begin(), text.end());
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    static_cast<void>(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                          text.data(), static_cast<int>(text.size()),
                                          wide.data(), required));
    return wide;
}

void ensure_event_source_registered() noexcept {
    HKEY key = nullptr;
    const LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kEventSourceRegistryPath,
                                        0, nullptr, REG_OPTION_NON_VOLATILE,
                                        KEY_SET_VALUE, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS || key == nullptr) return;
    const DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
                        EVENTLOG_INFORMATION_TYPE;
    static_cast<void>(RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD,
                                     reinterpret_cast<const BYTE*>(&types), sizeof(types)));
    RegCloseKey(key);
}

void report_event_rate_limited(WORD type, DWORD event_id, const std::string& message) noexcept {
    try {
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard lock(event_rate_mutex);
            auto& last = event_id == kEventSequenceRecovered ? last_recovery_event : last_failure_event;
            if (last.time_since_epoch().count() != 0 && now - last < kEventMinInterval) return;
            last = now;
        }
        ensure_event_source_registered();
        HANDLE source = RegisterEventSourceW(nullptr, kEventSourceName);
        if (source == nullptr) return;
        const auto wide = widen_utf8(message);
        const wchar_t* strings[] = {wide.c_str()};
        static_cast<void>(ReportEventW(source, type, 0, event_id, nullptr, 1, 0, strings, nullptr));
        DeregisterEventSource(source);
    } catch (...) {
    }
}

void write_recovery_marker(const std::filesystem::path& state_dir,
                           const std::string& detail) noexcept {
    try {
        std::ofstream output(state_dir / "sequence.recovery", std::ios::binary | std::ios::trunc);
        if (output) output << detail << '\n';
    } catch (...) {
    }
}

std::string read_recovery_marker(const std::filesystem::path& state_dir) noexcept {
    try {
        std::ifstream input(state_dir / "sequence.recovery", std::ios::binary);
        if (!input) return {};
        std::string line;
        std::getline(input, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return line;
    } catch (...) {
        return {};
    }
}

void note_recovery(const std::filesystem::path& state_dir, const std::string& detail) noexcept {
    std::cerr << "NAP sequence warning: " << detail << std::endl;
    write_recovery_marker(state_dir, detail);
    report_event_rate_limited(EVENTLOG_WARNING_TYPE, kEventSequenceRecovered, detail);
}

void note_failure(const std::string& detail) noexcept {
    std::cerr << "NAP sequence error: " << detail << std::endl;
    report_event_rate_limited(EVENTLOG_ERROR_TYPE, kEventSequenceFailure, detail);
}

[[noreturn]] void throw_win32(const std::string& operation,
                              const std::filesystem::path& path,
                              DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(),
                            operation + "(" + path.string() + ")");
}

class SequenceLock {
public:
    SequenceLock(const std::filesystem::path& path, std::chrono::milliseconds timeout)
        : path_(path) {
        handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw_win32("CreateFileW sequence lock", path_);
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            OVERLAPPED overlapped{};
            if (LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                           0, 1, 0, &overlapped) != FALSE) {
                locked_ = true;
                break;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_LOCK_VIOLATION && error != ERROR_IO_PENDING) {
                const HANDLE failed = handle_;
                handle_ = INVALID_HANDLE_VALUE;
                CloseHandle(failed);
                throw_win32("LockFileEx sequence lock", path_, error);
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                const HANDLE failed = handle_;
                handle_ = INVALID_HANDLE_VALUE;
                CloseHandle(failed);
                throw_win32("LockFileEx sequence lock timed out", path_, ERROR_LOCK_VIOLATION);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }

    ~SequenceLock() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        if (locked_) {
            OVERLAPPED overlapped{};
            static_cast<void>(UnlockFileEx(handle_, 0, 1, 0, &overlapped));
        }
        CloseHandle(handle_);
    }

    void release() {
        if (!locked_) return;
        OVERLAPPED overlapped{};
        if (UnlockFileEx(handle_, 0, 1, 0, &overlapped) == FALSE) {
            throw_win32("UnlockFileEx sequence lock", path_);
        }
        locked_ = false;
    }

    SequenceLock(const SequenceLock&) = delete;
    SequenceLock& operator=(const SequenceLock&) = delete;

private:
    std::filesystem::path path_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool locked_{false};
};

std::optional<std::string> read_text_if_exists(const std::filesystem::path& path,
                                               std::size_t max_bytes) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return std::nullopt;
        throw_win32("CreateFileW sequence read", path, error);
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(handle, &size) == FALSE) {
        const DWORD error = GetLastError();
        CloseHandle(handle);
        throw_win32("GetFileSizeEx sequence", path, error);
    }
    if (size.QuadPart < 0 || static_cast<unsigned long long>(size.QuadPart) > max_bytes) {
        CloseHandle(handle);
        throw std::runtime_error("NAP sequence state exceeds maximum size at " + path.string());
    }
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD total = 0;
    while (total < text.size()) {
        DWORD read = 0;
        const DWORD remaining = static_cast<DWORD>(text.size() - total);
        if (ReadFile(handle, text.data() + total, remaining, &read, nullptr) == FALSE) {
            const DWORD error = GetLastError();
            CloseHandle(handle);
            throw_win32("ReadFile sequence", path, error);
        }
        if (read == 0) break;
        total += read;
    }
    CloseHandle(handle);
    text.resize(total);
    return text;
}

void durable_write_text(const std::filesystem::path& path, const std::string& text) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw_win32("CreateFileW sequence write", path);
    DWORD total = 0;
    while (total < text.size()) {
        DWORD written = 0;
        const DWORD remaining = static_cast<DWORD>(text.size() - total);
        if (WriteFile(handle, text.data() + total, remaining, &written, nullptr) == FALSE) {
            const DWORD error = GetLastError();
            CloseHandle(handle);
            throw_win32("WriteFile sequence", path, error);
        }
        if (written == 0) {
            CloseHandle(handle);
            throw std::runtime_error("WriteFile sequence made no progress for " + path.string());
        }
        total += written;
    }
    if (FlushFileBuffers(handle) == FALSE) {
        const DWORD error = GetLastError();
        CloseHandle(handle);
        throw_win32("FlushFileBuffers sequence", path, error);
    }
    if (CloseHandle(handle) == FALSE) throw_win32("CloseHandle sequence", path);
}

SlotState read_slot(const std::filesystem::path& path) {
    SlotState slot;
    try {
        const auto text = read_text_if_exists(path, kMaxSequenceRecordBytes);
        if (!text) return slot;
        slot.exists = true;
        slot.value = parse_record(*text, path);
        slot.valid = true;
    } catch (const std::exception& error) {
        slot.exists = std::filesystem::exists(path);
        slot.error = error.what();
    }
    return slot;
}

SlotState read_legacy(const std::filesystem::path& path) {
    SlotState legacy;
    try {
        const auto text = read_text_if_exists(path, kMaxLegacySequenceBytes);
        if (!text) return legacy;
        legacy.exists = true;
        legacy.value = parse_decimal(*text, path);
        legacy.valid = true;
    } catch (const std::exception& error) {
        legacy.exists = std::filesystem::exists(path);
        legacy.error = error.what();
    }
    return legacy;
}

void write_slot(const std::filesystem::path& path, std::uint64_t sequence) {
    durable_write_text(path, make_record(sequence));
    const auto text = read_text_if_exists(path, kMaxSequenceRecordBytes);
    if (!text || parse_record(*text, path) != sequence) {
        throw std::runtime_error("NAP sequence durable write verification failed at " + path.string());
    }
}

void best_effort_write_legacy(const std::filesystem::path& state_dir,
                              std::uint64_t sequence) noexcept {
    try {
        durable_write_text(state_dir / "sequence", std::to_string(sequence) + "\n");
    } catch (const std::exception& error) {
        std::cerr << "NAP sequence warning: legacy compatibility mirror update failed: "
                  << error.what() << std::endl;
    }
}

std::uint64_t next_windows_sequence(const std::filesystem::path& state_dir,
                                    std::chrono::milliseconds lock_timeout) {
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", lock_timeout);
    const auto slot0_path = state_dir / "sequence.0";
    const auto slot1_path = state_dir / "sequence.1";
    auto slot0 = read_slot(slot0_path);
    auto slot1 = read_slot(slot1_path);

    std::uint64_t current = 0;
    if (!slot0.valid && !slot1.valid) {
        if (slot0.exists || slot1.exists) {
            throw std::runtime_error("NAP sequence state is unrecoverable: both redundant slots are invalid");
        }
        const auto legacy = read_legacy(state_dir / "sequence");
        if (!legacy.valid) {
            const std::string reason = legacy.exists ? legacy.error : "legacy sequence state is missing";
            throw std::runtime_error("NAP sequence state is unrecoverable: " + reason);
        }
        current = legacy.value;
        write_slot(slot0_path, current);
        write_slot(slot1_path, current);
        slot0 = SlotState{true, true, current, {}};
        slot1 = SlotState{true, true, current, {}};
        note_recovery(state_dir, "Migrated validated legacy NAP sequence " +
                                 std::to_string(current) + " into redundant crash-safe slots");
    } else if (slot0.valid && !slot1.valid) {
        current = slot0.value;
        write_slot(slot1_path, current);
        slot1 = SlotState{true, true, current, {}};
        note_recovery(state_dir, "Recovered NAP sequence state from sequence.0 at " +
                                 std::to_string(current) + " and repaired sequence.1");
    } else if (!slot0.valid && slot1.valid) {
        current = slot1.value;
        write_slot(slot0_path, current);
        slot0 = SlotState{true, true, current, {}};
        note_recovery(state_dir, "Recovered NAP sequence state from sequence.1 at " +
                                 std::to_string(current) + " and repaired sequence.0");
    } else {
        current = std::max(slot0.value, slot1.value);
    }

    if (current == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("NAP sequence state is exhausted");
    }
    const auto next = current + 1;
    const bool first_is_slot0 = slot0.value <= slot1.value;
    const auto& first_path = first_is_slot0 ? slot0_path : slot1_path;
    const auto& second_path = first_is_slot0 ? slot1_path : slot0_path;
    write_slot(first_path, next);
    // Do not expose N+1 to the caller until both durable copies contain it. If the
    // process or machine dies between these writes, the first copy advances and a
    // later allocation safely skips N+1 rather than ever reusing a sent sequence.
    write_slot(second_path, next);
    best_effort_write_legacy(state_dir, next);
    lock.release();
    return next;
}

void initialize_windows_sequence(const std::filesystem::path& state_dir,
                                 std::uint64_t initial_sequence) {
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", std::chrono::seconds(5));
    write_slot(state_dir / "sequence.0", initial_sequence);
    write_slot(state_dir / "sequence.1", initial_sequence);
    durable_write_text(state_dir / "sequence", std::to_string(initial_sequence) + "\n");
    std::error_code ec;
    std::filesystem::remove(state_dir / "sequence.recovery", ec);
    lock.release();
}

NapSequenceStatus inspect_windows_sequence(const std::filesystem::path& state_dir,
                                           std::chrono::milliseconds lock_timeout) {
    NapSequenceStatus status;
    SequenceLock lock(state_dir / "sequence.lock", lock_timeout);
    const auto slot0 = read_slot(state_dir / "sequence.0");
    const auto slot1 = read_slot(state_dir / "sequence.1");
    const auto legacy = read_legacy(state_dir / "sequence");
    status.slot0_valid = slot0.valid;
    status.slot1_valid = slot1.valid;
    status.legacy_valid = legacy.valid;
    status.recovery_detail = read_recovery_marker(state_dir);

    if (slot0.valid && slot1.valid) {
        status.health = NapSequenceHealth::Healthy;
        status.has_sequence = true;
        status.sequence = std::max(slot0.value, slot1.value);
        status.detail = slot0.value == slot1.value
            ? "both redundant sequence slots are valid and synchronized"
            : "both redundant sequence slots are valid; highest durable sequence selected";
    } else if (slot0.valid || slot1.valid) {
        status.health = NapSequenceHealth::Recovered;
        status.has_sequence = true;
        status.sequence = slot0.valid ? slot0.value : slot1.value;
        status.detail = "one redundant sequence slot is invalid; the next allocation will repair it";
    } else if (!slot0.exists && !slot1.exists && legacy.valid) {
        status.health = NapSequenceHealth::LegacyMigrationRequired;
        status.has_sequence = true;
        status.sequence = legacy.value;
        status.detail = "validated legacy sequence will migrate on the next NAP allocation";
    } else {
        status.health = NapSequenceHealth::Unrecoverable;
        status.detail = "no trustworthy redundant NAP sequence state is available";
        if (slot0.exists || slot1.exists) {
            status.detail += "; at least one redundant slot exists but neither is valid";
        } else if (legacy.exists && !legacy.valid && !legacy.error.empty()) {
            status.detail += "; " + legacy.error;
        }
    }
    lock.release();
    return status;
}
#else
[[noreturn]] void throw_errno(const std::string& operation,
                              const std::filesystem::path& path,
                              int error = errno) {
    throw std::system_error(error, std::generic_category(),
                            operation + "(" + path.string() + ")");
}

class SequenceLock {
public:
    SequenceLock(const std::filesystem::path& path, std::chrono::milliseconds timeout)
        : path_(path) {
        fd_ = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd_ < 0) throw_errno("open sequence lock", path_);
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (flock(fd_, LOCK_EX | LOCK_NB) != 0) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                const int error = errno;
                close(fd_);
                fd_ = -1;
                throw_errno("flock sequence lock", path_, error);
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                close(fd_);
                fd_ = -1;
                throw_errno("flock sequence lock timed out", path_, EWOULDBLOCK);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }
    ~SequenceLock() {
        if (fd_ < 0) return;
        static_cast<void>(flock(fd_, LOCK_UN));
        close(fd_);
    }
    void release() {
        if (fd_ < 0) return;
        if (flock(fd_, LOCK_UN) != 0) throw_errno("flock sequence unlock", path_);
        close(fd_);
        fd_ = -1;
    }
    SequenceLock(const SequenceLock&) = delete;
    SequenceLock& operator=(const SequenceLock&) = delete;
private:
    std::filesystem::path path_;
    int fd_{-1};
};

std::string read_legacy_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open NAP sequence state: " + path.string());
    std::string text((std::istreambuf_iterator<char>(input)), {});
    if (text.size() > kMaxLegacySequenceBytes) {
        throw std::runtime_error("NAP sequence state is malformed: value too large at " + path.string());
    }
    return text;
}

void durable_write_legacy(const std::filesystem::path& path, const std::string& text) {
    const int fd = open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) throw_errno("open sequence write", path);
    std::size_t offset = 0;
    while (offset < text.size()) {
        const ssize_t written = write(fd, text.data() + offset, text.size() - offset);
        if (written < 0) {
            const int error = errno;
            close(fd);
            throw_errno("write sequence", path, error);
        }
        if (written == 0) {
            close(fd);
            throw std::runtime_error("write sequence made no progress for " + path.string());
        }
        offset += static_cast<std::size_t>(written);
    }
    if (fsync(fd) != 0) {
        const int error = errno;
        close(fd);
        throw_errno("fsync sequence", path, error);
    }
    close(fd);
}
#endif

} // namespace

std::string to_string(NapSequenceHealth health) {
    switch (health) {
        case NapSequenceHealth::Healthy: return "HEALTHY";
        case NapSequenceHealth::Recovered: return "RECOVERED";
        case NapSequenceHealth::LegacyMigrationRequired: return "LEGACY_MIGRATION_REQUIRED";
        case NapSequenceHealth::Unrecoverable: return "UNRECOVERABLE";
    }
    return "UNRECOVERABLE";
}

std::uint64_t next_nap_sequence(const std::filesystem::path& state_dir,
                                std::chrono::milliseconds lock_timeout) {
#ifdef _WIN32
    try {
        return next_windows_sequence(state_dir, lock_timeout);
    } catch (const std::exception& error) {
        note_failure(std::string("NAP sequence allocation failed: ") + error.what());
        throw;
    }
#else
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", lock_timeout);
    const auto path = state_dir / "sequence";
    if (!std::filesystem::is_regular_file(path)) {
        throw std::runtime_error("NAP sequence state is missing: " + path.string());
    }
    const auto current = parse_decimal(read_legacy_text(path), path);
    if (current == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("NAP sequence state exhausted at " + path.string());
    }
    const auto next = current + 1;
    durable_write_legacy(path, std::to_string(next) + "\n");
    lock.release();
    return next;
#endif
}

void initialize_nap_sequence_state(const std::filesystem::path& state_dir,
                                   std::uint64_t initial_sequence) {
#ifdef _WIN32
    try {
        initialize_windows_sequence(state_dir, initial_sequence);
    } catch (const std::exception& error) {
        note_failure(std::string("NAP sequence initialization failed: ") + error.what());
        throw;
    }
#else
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", std::chrono::seconds(5));
    durable_write_legacy(state_dir / "sequence", std::to_string(initial_sequence) + "\n");
    lock.release();
#endif
}

NapSequenceStatus inspect_nap_sequence_state(const std::filesystem::path& state_dir,
                                             std::chrono::milliseconds lock_timeout) {
#ifdef _WIN32
    try {
        return inspect_windows_sequence(state_dir, lock_timeout);
    } catch (const std::exception& error) {
        NapSequenceStatus status;
        status.health = NapSequenceHealth::Unrecoverable;
        status.detail = error.what();
        return status;
    }
#else
    NapSequenceStatus status;
    try {
        SequenceLock lock(state_dir / "sequence.lock", lock_timeout);
        const auto path = state_dir / "sequence";
        const auto value = parse_decimal(read_legacy_text(path), path);
        status.health = NapSequenceHealth::Healthy;
        status.has_sequence = true;
        status.sequence = value;
        status.legacy_valid = true;
        status.detail = "legacy sequence state is valid";
        lock.release();
    } catch (const std::exception& error) {
        status.health = NapSequenceHealth::Unrecoverable;
        status.detail = error.what();
    }
    return status;
#endif
}

} // namespace neta
