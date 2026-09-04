#pragma once

#include "neta/antimalware.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace neta {

struct YaraXProviderConfig {
    std::filesystem::path rules_path;
    std::string ruleset_id{"default"};
    std::filesystem::path runtime_library_path{
        "/usr/local/lib/neta/yara-x/current/libyara_x_capi.so"};
    std::size_t max_artifact_bytes{64U * 1024U * 1024U};
    std::uint64_t timeout_seconds{5};
};

class YaraXProvider final : public AntimalwareProvider {
public:
    explicit YaraXProvider(YaraXProviderConfig config);
    ~YaraXProvider() override;

    YaraXProvider(const YaraXProvider&) = delete;
    YaraXProvider& operator=(const YaraXProvider&) = delete;
    YaraXProvider(YaraXProvider&&) noexcept;
    YaraXProvider& operator=(YaraXProvider&&) noexcept;

    [[nodiscard]] std::string name() const override;
    [[nodiscard]] AntimalwareEvidence scan(const ArtifactIdentity& artifact) override;
    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] std::string runtime_version() const;
    [[nodiscard]] std::string unavailable_reason() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace neta
