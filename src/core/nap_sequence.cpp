#include "neta/nap_sequence.hpp"

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

#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

namespace neta {
namespace {

constexpr std::size_t kMaxSequenceTextBytes = 64;

#ifdef _WIN32
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
                const auto failed_handle = handle_;
                handle_ = INVALID_HANDLE_VALUE;
                CloseHandle(failed_handle);
                throw_win32("LockFileEx sequence lock", path_, error);
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                const auto failed_handle = handle_;
                handle_ = INVALID_HANDLE_VALUE;
                CloseHandle(failed_handle);
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

    SequenceLock(const SequenceLock&) = delete;
    SequenceLock& operator=(const SequenceLock&) = delete;

private:
    std::filesystem::path path_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    bool locked_{false};
};

std::string read_sequence_text(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw_win32("CreateFileW sequence", path);

    LARGE_INTEGER size{};
    if (GetFileSizeEx(handle, &size) == FALSE) {
        const DWORD error = GetLastError();
        CloseHandle(handle);
        throw_win32("GetFileSizeEx sequence", path, error);
    }
    if (size.QuadPart < 0 || static_cast<unsigned long long>(size.QuadPart) > kMaxSequenceTextBytes) {
        CloseHandle(handle);
        throw std::runtime_error("NAP sequence state is malformed: unexpected file size at " +
                                 path.string());
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

void durable_write_sequence_text(const std::filesystem::path& path, const std::string& text) {
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
    CloseHandle(handle);
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

    SequenceLock(const SequenceLock&) = delete;
    SequenceLock& operator=(const SequenceLock&) = delete;

private:
    std::filesystem::path path_;
    int fd_{-1};
};

std::string read_sequence_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open NAP sequence state: " + path.string());
    std::string text((std::istreambuf_iterator<char>(input)), {});
    if (text.size() > kMaxSequenceTextBytes) {
        throw std::runtime_error("NAP sequence state is malformed: unexpected file size at " +
                                 path.string());
    }
    return text;
}

void durable_write_sequence_text(const std::filesystem::path& path, const std::string& text) {
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

std::uint64_t parse_sequence_text(std::string text, const std::filesystem::path& path) {
    if (!text.empty() && text.back() == '\n') text.pop_back();
    if (!text.empty() && text.back() == '\r') text.pop_back();
    if (text.empty()) {
        throw std::runtime_error("NAP sequence state is malformed: empty value at " + path.string());
    }
    for (const unsigned char c : text) {
        if (c < '0' || c > '9') {
            throw std::runtime_error("NAP sequence state is malformed: non-decimal data at " +
                                     path.string());
        }
    }
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::runtime_error("NAP sequence state is malformed: invalid integer at " +
                                 path.string());
    }
    return value;
}

} // namespace

std::uint64_t next_nap_sequence(const std::filesystem::path& state_dir,
                                std::chrono::milliseconds lock_timeout) {
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", lock_timeout);
    const auto path = state_dir / "sequence";
    if (!std::filesystem::is_regular_file(path)) {
        throw std::runtime_error("NAP sequence state is missing: " + path.string());
    }
    const auto current = parse_sequence_text(read_sequence_text(path), path);
    if (current == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("NAP sequence state exhausted at " + path.string());
    }
    const auto next = current + 1;
    durable_write_sequence_text(path, std::to_string(next) + "\n");
    return next;
}

void initialize_nap_sequence_state(const std::filesystem::path& state_dir,
                                   std::uint64_t initial_sequence) {
    std::filesystem::create_directories(state_dir);
    SequenceLock lock(state_dir / "sequence.lock", std::chrono::seconds(5));
    durable_write_sequence_text(state_dir / "sequence",
                                std::to_string(initial_sequence) + "\n");
}

} // namespace neta
