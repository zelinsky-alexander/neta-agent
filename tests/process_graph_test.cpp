#include "neta/process_finding_store.hpp"
#include "neta/process_graph.hpp"
#include "neta/process_findings.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

using namespace neta;

namespace {

ProcessExecEvent start_event(std::int64_t pid, std::uint64_t start_ns,
                             std::uint64_t observed_ns) {
    ProcessExecEvent event;
    event.type = ProcessExecEventType::Start;
    event.timestamp_ns = observed_ns;
    event.pid = pid;
    event.tgid = pid;
    event.process_start_time_ns = start_ns;
    return event;
}

bool has_finding(const std::vector<ProcessFinding>& findings, ProcessFindingKind kind) {
    return std::any_of(findings.begin(), findings.end(), [&](const ProcessFinding& finding) {
        return finding.kind == kind;
    });
}

}  // namespace

int main() {
    ProcessGraph graph(16);

    auto parent = start_event(100, 1'000, 10);
    parent.uid = 1000;
    parent.gid = 1000;
    parent.session_id = 7;
    parent.user_identity = "uid:1000";
    parent.integrity_level = "user";
    parent.elevated = false;
    parent.comm = "shell";
    parent.executable_path = "/bin/sh";
    parent.command_line = "/bin/sh -c child";
    parent.working_directory = "/tmp";
    assert(graph.observe(parent));

    auto child = start_event(101, 1'100, 20);
    child.parent_pid = 100;
    child.parent_tgid = 100;
    child.parent_process_start_time_ns = 1'000;
    child.uid = 1000;
    child.gid = 1000;
    child.session_id = 7;
    child.user_identity = "uid:1000";
    child.integrity_level = "user";
    child.elevated = false;
    child.comm = "child";
    child.executable_path = "/tmp/child";
    child.command_line = "/tmp/child --test";
    child.working_directory = "/tmp";
    assert(graph.observe(child));
    assert(graph.active_count() == 2);

    const ProcessInstanceKey parent_key{100, 1'000, std::nullopt};
    const ProcessInstanceKey child_key{101, 1'100, std::nullopt};
    const auto child_node = graph.find(child_key);
    assert(child_node);
    assert(child_node->parent);
    assert(*child_node->parent == parent_key);
    assert(child_node->command_line == "/tmp/child --test");
    assert(child_node->working_directory == "/tmp");
    assert(child_node->session_id == 7);
    assert(child_node->elevated == false);

    ProcessFindingEngine snapshot_engine;
    const auto initial_findings = snapshot_engine.evaluate_snapshot(graph);
    assert(has_finding(initial_findings, ProcessFindingKind::ExecFromTransientPath));

    // MS5.2 persistence: durable process identity, deduplicated finding key,
    // occurrence count, and retry/report state all survive beyond the graph.
    {
        const auto db = std::filesystem::temp_directory_path() / "neta-process-findings-ms52-test.sqlite";
        std::error_code ec;
        std::filesystem::remove(db, ec);
        std::filesystem::remove(db.string() + "-wal", ec);
        std::filesystem::remove(db.string() + "-shm", ec);
        {
            ProcessFindingStore store(db);
            store.upsert_process(*graph.find(parent_key));
            store.upsert_process(*child_node);
            const auto transient = std::find_if(initial_findings.begin(), initial_findings.end(), [](const ProcessFinding& finding) {
                return finding.kind == ProcessFindingKind::ExecFromTransientPath;
            });
            assert(transient != initial_findings.end());
            const auto first = store.upsert_finding(*transient);
            assert(first.finding_id.starts_with("FINDING-PROC-"));
            assert(first.finding_key.find("PROCESS_EXEC_FROM_TRANSIENT_PATH") != std::string::npos);
            assert(first.report_state == "PENDING");
            assert(first.occurrence_count == 1);
            const auto second = store.upsert_finding(*transient);
            assert(second.finding_id == first.finding_id);
            assert(second.occurrence_count == 2);
            const auto pending = store.pending_for_report(10, 1000, 0);
            assert(pending.size() == 1);
            store.mark_report_attempt(first.finding_id, 1000);
            store.mark_reported(first.finding_id, 1100);
            const auto recent = store.recent_findings(10);
            assert(recent.size() == 1);
            assert(recent.front().report_state == "REPORTED");
        }
        std::filesystem::remove(db, ec);
        std::filesystem::remove(db.string() + "-wal", ec);
        std::filesystem::remove(db.string() + "-shm", ec);
    }

    ProcessExecEvent child_exit;
    child_exit.type = ProcessExecEventType::Exit;
    child_exit.timestamp_ns = 30;
    child_exit.pid = 101;
    child_exit.tgid = 101;
    child_exit.process_start_time_ns = 1'100;
    child_exit.exit_code = 0;
    assert(graph.observe(child_exit));
    assert(graph.active_count() == 1);
    const auto exited_child = graph.find(child_key);
    assert(exited_child && exited_child->exited_at_ns == 30);
    assert(exited_child->exit_code == 0);

    auto reused_pid = start_event(101, 2'100, 40);
    reused_pid.parent_tgid = 100;
    reused_pid.parent_process_start_time_ns = 1'000;
    reused_pid.executable_path = "/tmp/reused";
    assert(graph.observe(reused_pid));
    const ProcessInstanceKey reused_key{101, 2'100, std::nullopt};
    assert(graph.find(reused_key));
    assert(graph.find(child_key));
    assert(graph.active_count() == 2);

    auto orphan_child = start_event(200, 4'000, 45);
    orphan_child.parent_tgid = 199;
    orphan_child.parent_process_start_time_ns = 3'900;
    assert(graph.observe(orphan_child));
    const ProcessInstanceKey orphan_key{200, 4'000, std::nullopt};
    const ProcessInstanceKey orphan_parent_key{199, 3'900, std::nullopt};
    const auto orphan_node = graph.find(orphan_key);
    assert(orphan_node && orphan_node->parent);
    assert(*orphan_node->parent == orphan_parent_key);

    auto duplicate_pid_instance = start_event(101, 3'100, 50);
    duplicate_pid_instance.executable_path = "/tmp/synthetic-second-active";
    assert(graph.observe(duplicate_pid_instance));

    ProcessExecEvent ambiguous_exit;
    ambiguous_exit.type = ProcessExecEventType::Exit;
    ambiguous_exit.timestamp_ns = 60;
    ambiguous_exit.pid = 101;
    ambiguous_exit.tgid = 101;
    assert(!graph.observe(ambiguous_exit));
    assert(graph.health().ambiguous_exit_events == 1);

    ProcessExecEvent unstable_start;
    unstable_start.type = ProcessExecEventType::Start;
    unstable_start.timestamp_ns = 70;
    unstable_start.pid = 999;
    unstable_start.tgid = 999;
    assert(!graph.observe(unstable_start));
    assert(graph.health().rejected_without_stable_identity == 1);

    const auto nodes = graph.snapshot();
    assert(nodes.size() == 5);

    // Cross-platform transient path normalization.
    {
        ProcessGraph windows_graph;
        auto win = start_event(300, 9'000, 9'000);
        win.process_start_time_ns.reset();
        win.platform_process_key = 777;
        win.executable_path = "C:\\Users\\lab\\AppData\\Local\\Temp\\neta-lab.exe";
        win.comm = "neta-lab.exe";
        assert(windows_graph.observe(win));
        const auto findings = snapshot_engine.evaluate_snapshot(windows_graph);
        assert(has_finding(findings, ProcessFindingKind::ExecFromTransientPath));
    }

    // Parent/child semantic findings.
    {
        ProcessGraph finding_graph;
        auto service = start_event(400, 10'000, 10'000);
        service.executable_path = "/usr/sbin/nginx";
        service.comm = "nginx";
        service.elevated = false;
        assert(finding_graph.observe(service));

        auto shell = start_event(401, 10'100, 10'100);
        shell.parent_tgid = 400;
        shell.parent_process_start_time_ns = 10'000;
        shell.executable_path = "/bin/sh";
        shell.comm = "sh";
        shell.elevated = true;
        assert(finding_graph.observe(shell));
        const auto findings = snapshot_engine.evaluate_snapshot(finding_graph);
        assert(has_finding(findings, ProcessFindingKind::ShellFromUnexpectedParent));
        assert(has_finding(findings, ProcessFindingKind::UnexpectedElevation));
    }

    // Event-time fan-out and short-lived burst rules.
    {
        ProcessFindingConfig config;
        config.fanout_count = 3;
        config.fanout_window_ns = 1'000;
        config.short_lived_count = 3;
        config.short_lived_max_ns = 100;
        config.short_lived_window_ns = 1'000;
        ProcessFindingEngine engine(config);
        ProcessGraph event_graph;

        auto runner = start_event(500, 20'000, 20'000);
        runner.executable_path = "/usr/bin/runner";
        runner.comm = "runner";
        assert(event_graph.observe(runner));

        std::vector<ProcessFinding> start_findings;
        std::vector<ProcessFinding> exit_findings;
        for (std::int64_t pid = 501; pid <= 503; ++pid) {
            const auto when = 20'100 + static_cast<std::uint64_t>(pid - 501) * 100;
            auto helper = start_event(pid, when, when);
            helper.parent_tgid = 500;
            helper.parent_process_start_time_ns = 20'000;
            helper.executable_path = "/usr/bin/helper";
            helper.comm = "helper";
            assert(event_graph.observe(helper));
            start_findings = engine.observe(helper, event_graph);

            ProcessExecEvent exit = helper;
            exit.type = ProcessExecEventType::Exit;
            exit.timestamp_ns = when + 20;
            assert(event_graph.observe(exit));
            exit_findings = engine.observe(exit, event_graph);
        }
        assert(has_finding(start_findings, ProcessFindingKind::RapidChildFanout));
        assert(has_finding(exit_findings, ProcessFindingKind::ShortLivedProcessBurst));
    }

    std::cout << "process graph, MS5.1 findings, and MS5.2 persistence tests passed\n";
    return 0;
}
