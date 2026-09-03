#include "neta/yara_x_provider.hpp"

#include "neta/crypto.hpp"

#include <cstdint>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(NETA_HAVE_YARA_X)
#include <yara_x.h>
#endif

namespace neta {

namespace {

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("unable to open YARA-X rules file: " + path.string());
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::vector<std::uint8_t> read_artifact(const std::filesystem::path& path,
                                        std::size_t max_bytes) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("unable to open artifact: " + path.string());
    }

    const auto end = input.tellg();
    if (end < 0) {
        throw std::runtime_error("unable to determine artifact size: " + path.string());
    }
    const auto length = static_cast<std::uintmax_t>(end);
    if (length > max_bytes) {
        throw std::runtime_error("artifact exceeds configured YARA-X scan limit");
    }

    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(length));
    if (!data.empty() && !input.read(reinterpret_cast<char*>(data.data()),
                                     static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("unable to read artifact: " + path.string());
    }
    return data;
}

}  // namespace

class YaraXProvider::Impl {
public:
    explicit Impl(YaraXProviderConfig config) : config_(std::move(config)) {
#if defined(NETA_HAVE_YARA_X)
        const auto source = read_text_file(config_.rules_path);
        ruleset_sha256_ = sha256_hex(source);
        if (yrx_compile(source.c_str(), &rules_) != YRX_SUCCESS) {
            const char* error = yrx_last_error();
            throw std::runtime_error(std::string("unable to compile YARA-X rules: ") +
                                     (error != nullptr ? error : "unknown error"));
        }
#else
        (void)config_;
#endif
    }

    ~Impl() {
#if defined(NETA_HAVE_YARA_X)
        if (rules_ != nullptr) {
            yrx_rules_destroy(rules_);
        }
#endif
    }

    [[nodiscard]] bool available() const noexcept {
#if defined(NETA_HAVE_YARA_X)
        return rules_ != nullptr;
#else
        return false;
#endif
    }

    [[nodiscard]] AntimalwareEvidence scan(const ArtifactIdentity& artifact) {
        AntimalwareEvidence result;
        result.provider_name = "yara-x";
#if defined(NETA_YARA_X_VERSION)
        result.provider_version = NETA_YARA_X_VERSION;
#else
        result.provider_version = "unavailable";
#endif
        result.ruleset_id = config_.ruleset_id;
        result.ruleset_sha256 = ruleset_sha256_;

#if !defined(NETA_HAVE_YARA_X)
        result.state = AntimalwareScanState::Unsupported;
        result.detail = "NETA was built without the YARA-X C API";
        return result;
#else
        try {
            const auto data = read_artifact(artifact.path, config_.max_artifact_bytes);
            YRX_SCANNER* scanner = nullptr;
            if (yrx_scanner_create(rules_, &scanner) != YRX_SUCCESS || scanner == nullptr) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = "unable to create YARA-X scanner";
                return result;
            }

            struct ScannerGuard {
                YRX_SCANNER* scanner;
                ~ScannerGuard() {
                    if (scanner != nullptr) {
                        yrx_scanner_destroy(scanner);
                    }
                }
            } guard{scanner};

            auto on_match = [](const YRX_RULE* rule, void* user_data) {
                auto* evidence = static_cast<AntimalwareEvidence*>(user_data);
                const std::uint8_t* identifier = nullptr;
                std::size_t identifier_len = 0;
                const std::uint8_t* name_space = nullptr;
                std::size_t namespace_len = 0;

                AntimalwareMatch match;
                if (yrx_rule_identifier(rule, &identifier, &identifier_len) == YRX_SUCCESS &&
                    identifier != nullptr) {
                    match.rule_name.assign(reinterpret_cast<const char*>(identifier), identifier_len);
                }
                if (yrx_rule_namespace(rule, &name_space, &namespace_len) == YRX_SUCCESS &&
                    name_space != nullptr) {
                    match.rule_namespace.assign(reinterpret_cast<const char*>(name_space), namespace_len);
                }
                evidence->matches.push_back(std::move(match));
            };

            if (yrx_scanner_on_matching_rule(scanner, on_match, &result) != YRX_SUCCESS) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = "unable to configure YARA-X match callback";
                return result;
            }
            if (yrx_scanner_set_timeout(scanner, config_.timeout_seconds) != YRX_SUCCESS) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = "unable to configure YARA-X scan timeout";
                return result;
            }

            const auto scan_result = yrx_scanner_scan(scanner, data.data(), data.size());
            if (scan_result == YRX_SCAN_TIMEOUT) {
                result.state = AntimalwareScanState::Inconclusive;
                result.detail = "YARA-X scan timed out";
                return result;
            }
            if (scan_result != YRX_SUCCESS) {
                result.state = AntimalwareScanState::ScanError;
                const char* error = yrx_last_error();
                result.detail = error != nullptr ? error : "YARA-X scan failed";
                return result;
            }

            result.state = result.matches.empty() ? AntimalwareScanState::NoMatch
                                                  : AntimalwareScanState::Match;
            return result;
        } catch (const std::exception& error) {
            result.state = AntimalwareScanState::ScanError;
            result.detail = error.what();
            return result;
        }
#endif
    }

private:
    YaraXProviderConfig config_;
    std::string ruleset_sha256_;
#if defined(NETA_HAVE_YARA_X)
    YRX_RULES* rules_{nullptr};
#endif
};

YaraXProvider::YaraXProvider(YaraXProviderConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

YaraXProvider::~YaraXProvider() = default;
YaraXProvider::YaraXProvider(YaraXProvider&&) noexcept = default;
YaraXProvider& YaraXProvider::operator=(YaraXProvider&&) noexcept = default;

std::string YaraXProvider::name() const {
    return "yara-x";
}

AntimalwareEvidence YaraXProvider::scan(const ArtifactIdentity& artifact) {
    return impl_->scan(artifact);
}

bool YaraXProvider::available() const noexcept {
    return impl_->available();
}

}  // namespace neta
