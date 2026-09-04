#include "neta/yara_x_provider.hpp"

#include "neta/crypto.hpp"

#include <dlfcn.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta {

namespace {

struct YrxRules;
struct YrxScanner;
struct YrxRule;

using YrxResult = int;
constexpr YrxResult kYrxSuccess = 0;
constexpr YrxResult kYrxScanTimeout = 4;
using YrxRuleCallback = void (*)(const YrxRule*, void*);

struct YaraXApi {
    using CompileFn = YrxResult (*)(const char*, YrxRules**);
    using LastErrorFn = const char* (*)();
    using RulesDestroyFn = void (*)(YrxRules*);
    using ScannerCreateFn = YrxResult (*)(const YrxRules*, YrxScanner**);
    using ScannerDestroyFn = void (*)(YrxScanner*);
    using ScannerOnMatchingRuleFn = YrxResult (*)(YrxScanner*, YrxRuleCallback, void*);
    using ScannerSetTimeoutFn = YrxResult (*)(YrxScanner*, std::uint64_t);
    using ScannerScanFn = YrxResult (*)(YrxScanner*, const std::uint8_t*, std::size_t);
    using RuleIdentifierFn = YrxResult (*)(const YrxRule*, const std::uint8_t**, std::size_t*);
    using RuleNamespaceFn = YrxResult (*)(const YrxRule*, const std::uint8_t**, std::size_t*);

    void* handle{nullptr};
    CompileFn compile{nullptr};
    LastErrorFn last_error{nullptr};
    RulesDestroyFn rules_destroy{nullptr};
    ScannerCreateFn scanner_create{nullptr};
    ScannerDestroyFn scanner_destroy{nullptr};
    ScannerOnMatchingRuleFn scanner_on_matching_rule{nullptr};
    ScannerSetTimeoutFn scanner_set_timeout{nullptr};
    ScannerScanFn scanner_scan{nullptr};
    RuleIdentifierFn rule_identifier{nullptr};
    RuleNamespaceFn rule_namespace{nullptr};
};

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("unable to open YARA-X rules file: " + path.string());
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string read_optional_single_line(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) return {};
    std::string value;
    std::getline(input, value);
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ' ||
                              value.back() == '\t')) {
        value.pop_back();
    }
    return value;
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

template <typename Fn>
Fn load_symbol(void* handle, const char* name) {
    ::dlerror();
    void* raw = ::dlsym(handle, name);
    const char* error = ::dlerror();
    if (error != nullptr || raw == nullptr) {
        throw std::runtime_error(std::string("missing YARA-X runtime symbol ") + name +
                                 (error != nullptr ? std::string(": ") + error : std::string{}));
    }

    static_assert(sizeof(Fn) == sizeof(raw));
    Fn function{};
    std::memcpy(&function, &raw, sizeof(function));
    return function;
}

YaraXApi load_api(const std::filesystem::path& library_path) {
    YaraXApi api;
    api.handle = ::dlopen(library_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (api.handle == nullptr) {
        const char* error = ::dlerror();
        throw std::runtime_error("unable to load YARA-X runtime " + library_path.string() +
                                 (error != nullptr ? std::string(": ") + error : std::string{}));
    }

    // Keep the runtime loaded even if ABI validation fails. YARA-X documents special
    // process-wide finalization requirements before unloading a dynamically loaded
    // runtime, and NETA deliberately has no hot-unload semantics.
    api.compile = load_symbol<YaraXApi::CompileFn>(api.handle, "yrx_compile");
    api.last_error = load_symbol<YaraXApi::LastErrorFn>(api.handle, "yrx_last_error");
    api.rules_destroy = load_symbol<YaraXApi::RulesDestroyFn>(api.handle, "yrx_rules_destroy");
    api.scanner_create = load_symbol<YaraXApi::ScannerCreateFn>(api.handle, "yrx_scanner_create");
    api.scanner_destroy = load_symbol<YaraXApi::ScannerDestroyFn>(api.handle, "yrx_scanner_destroy");
    api.scanner_on_matching_rule = load_symbol<YaraXApi::ScannerOnMatchingRuleFn>(
        api.handle, "yrx_scanner_on_matching_rule");
    api.scanner_set_timeout = load_symbol<YaraXApi::ScannerSetTimeoutFn>(
        api.handle, "yrx_scanner_set_timeout");
    api.scanner_scan = load_symbol<YaraXApi::ScannerScanFn>(api.handle, "yrx_scanner_scan");
    api.rule_identifier = load_symbol<YaraXApi::RuleIdentifierFn>(api.handle, "yrx_rule_identifier");
    api.rule_namespace = load_symbol<YaraXApi::RuleNamespaceFn>(api.handle, "yrx_rule_namespace");

    return api;
}

std::string last_error_or(const YaraXApi& api, std::string fallback) {
    if (api.last_error != nullptr) {
        const char* error = api.last_error();
        if (error != nullptr && *error != '\0') return error;
    }
    return fallback;
}

}  // namespace

class YaraXProvider::Impl {
public:
    explicit Impl(YaraXProviderConfig config) : config_(std::move(config)) {
#if !defined(NETA_YARA_X_RUNTIME_ENABLED)
        unavailable_state_ = AntimalwareScanState::Unsupported;
        unavailable_reason_ = "YARA-X runtime provider disabled at build time";
        return;
#else
        if (const char* override_path = std::getenv("NETA_YARAX_LIBRARY");
            override_path != nullptr && *override_path != '\0') {
            config_.runtime_library_path = override_path;
        }

        runtime_version_ = read_optional_single_line(config_.runtime_library_path.parent_path() / "VERSION");
        if (runtime_version_.empty()) runtime_version_ = "unknown";

        try {
            api_ = load_api(config_.runtime_library_path);
        } catch (const std::exception& error) {
            unavailable_state_ = AntimalwareScanState::Unsupported;
            unavailable_reason_ = error.what();
            return;
        }

        try {
            const auto source = read_text_file(config_.rules_path);
            ruleset_sha256_ = sha256_hex(source);
            if (api_.compile(source.c_str(), &rules_) != kYrxSuccess || rules_ == nullptr) {
                unavailable_state_ = AntimalwareScanState::ScanError;
                unavailable_reason_ = last_error_or(api_, "unable to compile YARA-X rules");
                return;
            }
        } catch (const std::exception& error) {
            unavailable_state_ = AntimalwareScanState::ScanError;
            unavailable_reason_ = error.what();
            return;
        }
#endif
    }

    ~Impl() {
        if (rules_ != nullptr && api_.rules_destroy != nullptr) {
            api_.rules_destroy(rules_);
            rules_ = nullptr;
        }
        // Do not dlclose(api_.handle). The YARA-X C API requires special global
        // finalization before unloading. The operating system releases it at process exit.
    }

    [[nodiscard]] bool available() const noexcept {
        return rules_ != nullptr;
    }

    [[nodiscard]] std::string runtime_version() const {
        return runtime_version_;
    }

    [[nodiscard]] std::string unavailable_reason() const {
        return unavailable_reason_;
    }

    [[nodiscard]] AntimalwareEvidence scan(const ArtifactIdentity& artifact) {
        AntimalwareEvidence result;
        result.provider_name = "yara-x";
        result.provider_version = runtime_version_.empty() ? "unavailable" : runtime_version_;
        result.ruleset_id = config_.ruleset_id;
        result.ruleset_sha256 = ruleset_sha256_;

        if (!available()) {
            result.state = unavailable_state_;
            result.detail = unavailable_reason_;
            return result;
        }

        try {
            const auto data = read_artifact(artifact.path, config_.max_artifact_bytes);
            YrxScanner* scanner = nullptr;
            if (api_.scanner_create(rules_, &scanner) != kYrxSuccess || scanner == nullptr) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = last_error_or(api_, "unable to create YARA-X scanner");
                return result;
            }

            struct ScannerGuard {
                YaraXApi* api;
                YrxScanner* scanner;
                ~ScannerGuard() {
                    if (scanner != nullptr) api->scanner_destroy(scanner);
                }
            } guard{&api_, scanner};

            struct MatchContext {
                YaraXApi* api;
                AntimalwareEvidence* evidence;
            } context{&api_, &result};

            auto on_match = [](const YrxRule* rule, void* user_data) {
                auto* context = static_cast<MatchContext*>(user_data);
                const std::uint8_t* identifier = nullptr;
                std::size_t identifier_len = 0;
                const std::uint8_t* name_space = nullptr;
                std::size_t namespace_len = 0;

                AntimalwareMatch match;
                if (context->api->rule_identifier(rule, &identifier, &identifier_len) == kYrxSuccess &&
                    identifier != nullptr) {
                    match.rule_name.assign(reinterpret_cast<const char*>(identifier), identifier_len);
                }
                if (context->api->rule_namespace(rule, &name_space, &namespace_len) == kYrxSuccess &&
                    name_space != nullptr) {
                    match.rule_namespace.assign(reinterpret_cast<const char*>(name_space), namespace_len);
                }
                context->evidence->matches.push_back(std::move(match));
            };

            if (api_.scanner_on_matching_rule(scanner, on_match, &context) != kYrxSuccess) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = last_error_or(api_, "unable to configure YARA-X match callback");
                return result;
            }
            if (api_.scanner_set_timeout(scanner, config_.timeout_seconds) != kYrxSuccess) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = last_error_or(api_, "unable to configure YARA-X scan timeout");
                return result;
            }

            const auto scan_result = api_.scanner_scan(scanner, data.data(), data.size());
            if (scan_result == kYrxScanTimeout) {
                result.state = AntimalwareScanState::Inconclusive;
                result.detail = "YARA-X scan timed out";
                return result;
            }
            if (scan_result != kYrxSuccess) {
                result.state = AntimalwareScanState::ScanError;
                result.detail = last_error_or(api_, "YARA-X scan failed");
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
    }

private:
    YaraXProviderConfig config_;
    YaraXApi api_;
    YrxRules* rules_{nullptr};
    std::string ruleset_sha256_;
    std::string runtime_version_;
    AntimalwareScanState unavailable_state_{AntimalwareScanState::Unsupported};
    std::string unavailable_reason_{"YARA-X runtime unavailable"};
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

std::string YaraXProvider::runtime_version() const {
    return impl_->runtime_version();
}

std::string YaraXProvider::unavailable_reason() const {
    return impl_->unavailable_reason();
}

}  // namespace neta
