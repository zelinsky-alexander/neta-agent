#include "neta/process_findings.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {

neta::ProcessExecEvent start(std::int64_t pid, std::uint64_t when,
                             std::string image, std::string comm,
                             std::int64_t parent = 0) {
    neta::ProcessExecEvent event;
    event.type = neta::ProcessExecEventType::Start;
    event.timestamp_ns = when;
    event.pid = pid;
    event.tgid = pid;
    event.process_start_time_ns = when;
    event.executable_path = std::move(image);
    event.comm = std::move(comm);
    if (parent > 0) {
        event.parent_pid = parent;
        event.parent_tgid = parent;
    }
    return event;
}

bool has(const std::vector<neta::ProcessFinding>& findings, neta::ProcessFindingKind kind) {
    return std::any_of(findings.begin(), findings.end(), [&](const auto& finding) {
        return finding.kind == kind;
    });
}

}  // namespace

int main() {
    using namespace neta;

    // Portable transient-path rule: Linux and Windows spellings normalize to one semantic rule.
    {
        ProcessGraph graph;
        auto linux_event = start(10, 100, "/tmp/neta-lab-tool", "neta-lab-tool");
        assert(graph.observe(linux_event));
        ProcessFindingEngine engine;
        auto findings = engine.evaluate_snapshot(graph);
        assert(has(findings, ProcessFindingKind::ExecFromTransientPath));

        ProcessGraph windows_graph;
        auto windows_event = start(11, 101,
            "C:\\Users\\lab\\AppData\\Local\\Temp\\neta-lab-tool.exe", "neta-lab-tool.exe");
        windows_event.platform_process_key = 9001;
        windows_event.process_start_time_ns.reset();
        assert(windows_graph.observe(windows_event));
        findings = engine.evaluate_snapshot(windows_graph);
        assert(has(findings, ProcessFindingKind::ExecFromTransientPath));
    }

    // Shell from a non-interactive parent and an observed privilege boundary transition.
    {
        ProcessGraph graph;
        auto parent = start(20, 200, "/usr/sbin/nginx", "nginx");
        parent.elevated = false;
        assert(graph.observe(parent));

        auto child = start(21, 210, "/bin/sh", "sh", 20);
        child.parent_process_start_time_ns = 200;
        child.elevated = true;
        assert(graph.observe(child));

        ProcessFindingEngine engine;
        const auto findings = engine.evaluate_snapshot(graph);
        assert(has(findings, ProcessFindingKind::ShellFromUnexpectedParent));
        assert(has(findings, ProcessFindingKind::UnexpectedElevation));
    }

    // Rapid child fan-out is event-time and tied to the stable parent instance.
    {
        ProcessFindingConfig config;
        config.fanout_count = 3;
        config.fanout_window_ns = 1'000;
        ProcessFindingEngine engine(config);
        ProcessGraph graph;
        auto parent = start(30, 1'000, "/usr/bin/python3", "python3");
        assert(graph.observe(parent));

        std::vector<ProcessFinding> last;
        for (std::int64_t pid = 31; pid <= 33; ++pid) {
            auto child = start(pid, 1'000 + static_cast<std::uint64_t>(pid - 30) * 10,
                               "/usr/bin/true", "true", 30);
            child.parent_process_start_time_ns = 1'000;
            assert(graph.observe(child));
            last = engine.observe(child, graph);
        }
        assert(has(last, ProcessFindingKind::RapidChildFanout));
    }

    // Short-lived burst fires only after enough observed start/exit pairs.
    {
        ProcessFindingConfig config;
        config.short_lived_count = 3;
        config.short_lived_max_ns = 100;
        config.short_lived_window_ns = 1'000;
        ProcessFindingEngine engine(config);
        ProcessGraph graph;
        auto parent = start(40, 2'000, "/usr/bin/worker", "worker");
        assert(graph.observe(parent));

        std::vector<ProcessFinding> last;
        for (std::int64_t pid = 41; pid <= 43; ++pid) {
            const auto started = 2'100 + static_cast<std::uint64_t>(pid - 41) * 100;
            auto child = start(pid, started, "/usr/bin/helper", "helper", 40);
            child.parent_process_start_time_ns = 2'000;
            assert(graph.observe(child));
            static_cast<void>(engine.observe(child, graph));

            ProcessExecEvent exit = child;
            exit.type = ProcessExecEventType::Exit;
            exit.timestamp_ns = started + 20;
            assert(graph.observe(exit));
            last = engine.observe(exit, graph);
        }
        assert(has(last, ProcessFindingKind::ShortLivedProcessBurst));
    }

    return 0;
}
