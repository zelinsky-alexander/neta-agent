#include "neta/exec_antimalware_monitor.hpp"
#include "neta/platform.hpp"
#include "neta/yara_x_provider.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace {

constexpr int kSkip = 77;
constexpr auto kPollSlice = std::chrono::milliseconds(200);
constexpr auto kDeadline = std::chrono::seconds(5);

bool same_file(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    std::error_code error;
    const bool equivalent = std::filesystem::equivalent(lhs, rhs, error);
    if (!error) return equivalent;
    return lhs.lexically_normal() == rhs.lexically_normal();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: yara_exec_trigger_integration <trigger-binary> <rules-file>\n";
        return 2;
    }

    const std::filesystem::path trigger = std::filesystem::absolute(argv[1]);
    const std::filesystem::path rules = std::filesystem::absolute(argv[2]);

    neta::YaraXProviderConfig yara_config;
    yara_config.rules_path = rules;
    yara_config.ruleset_id = "neta-exec-trigger-test";
    auto yara = std::make_unique<neta::YaraXProvider>(std::move(yara_config));
    if (!yara->available()) {
        std::cout << "SKIP: YARA-X runtime unavailable: " << yara->unavailable_reason() << '\n';
        return kSkip;
    }
    std::cout << "YARA-X runtime version=" << yara->runtime_version() << '\n';

    auto observer = neta::platform::make_process_exec_observer();
    if (!observer->capability().available()) {
        std::cout << "SKIP: sched_process_exec observer unavailable: "
                  << observer->capability().unavailable_reason << '\n';
        return kSkip;
    }

    neta::AntimalwareProviderSet providers;
    providers.add(std::move(yara));
    neta::ExecAntimalwareMonitor monitor(std::move(observer), std::move(providers));

    const pid_t child = ::fork();
    if (child < 0) {
        std::perror("fork");
        return 1;
    }
    if (child == 0) {
        const std::string target = trigger.string();
        ::execl(target.c_str(), target.c_str(), static_cast<char*>(nullptr));
        std::perror("execl");
        _exit(127);
    }

    int child_status = 0;
    if (::waitpid(child, &child_status, 0) < 0) {
        std::perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        std::cerr << "trigger executable failed\n";
        return 1;
    }

    const auto deadline = std::chrono::steady_clock::now() + kDeadline;
    while (std::chrono::steady_clock::now() < deadline) {
        for (const auto& result : monitor.poll(kPollSlice)) {
            if (!result.exec.tgid || *result.exec.tgid != static_cast<std::int64_t>(child)) continue;
            if (!same_file(result.artifact.path, trigger)) continue;

            std::cout << "EXEC pid=" << *result.exec.tgid
                      << " path=" << result.artifact.path
                      << " sha256=" << result.artifact.sha256.value_or("unavailable") << '\n';

            for (const auto& evidence : result.evidence) {
                std::cout << "provider=" << evidence.provider_name
                          << " version=" << evidence.provider_version
                          << " state=" << neta::to_string(evidence.state)
                          << " matches=" << evidence.matches.size() << '\n';
                for (const auto& match : evidence.matches) {
                    std::cout << "rule=" << match.rule_name << '\n';
                    if (evidence.provider_name == "yara-x" &&
                        match.rule_name == "neta_exec_trigger_marker" &&
                        evidence.state == neta::AntimalwareScanState::Match) {
                        std::cout << "PASS: sched_process_exec triggered YARA-X match\n";
                        return 0;
                    }
                }
            }
            std::cerr << "exec event was captured, but expected YARA-X rule did not match\n";
            return 1;
        }
    }

    std::cerr << "timed out waiting for sched_process_exec event for trigger PID\n";
    return 1;
}
