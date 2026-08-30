#include "neta/storage_maintenance.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>

int main() {
    using namespace std::chrono_literals;
    const auto path = std::filesystem::temp_directory_path() / "neta-ms2-maintenance.sqlite";
    std::filesystem::remove(path);
    {
        neta::HistoryStore store(path);
        neta::StorageMaintenance maintenance(store, 10'000'000, 30s);
        const auto start = neta::StorageMaintenance::Clock::time_point{};
        assert(maintenance.run_if_due(start));
        assert(!maintenance.run_if_due(start + 29s));
        assert(maintenance.run_if_due(start + 30s));
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
    std::cout << "Storage maintenance tests passed\n";
}
