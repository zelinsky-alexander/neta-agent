#include "neta/cli/process_command.hpp"

#include "neta/platform.hpp"
#include "neta/process_graph.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace neta::cli {
namespace {

volatile std::sig_atomic_t process_stop_requested = 0;

void handle_process_stop(int) { process_stop_requested = 1; }

class ProcessSignalHandlers {
public:
    ProcessSignalHandlers()
        : previous_sigint_(std::signal(SIGINT, handle_process_stop)),
          previous_sigterm_(std::signal(SIGTERM, handle_process_stop)) {
        process_stop_requested = 0;
    }
    ~ProcessSignalHandlers() {
        std::signal(SIGINT, previous_sigint_);
        std::signal(SIGTERM, previous_sigterm_);
    }
private:
    using Handler = void (*)(int);
    Handler previous_sigint_;
    Handler previous_sigterm_;
};

ProcessInstanceKey event_key(const ProcessExecEvent& event) {
    ProcessInstanceKey key;
    key.pid = event.tgid.value_or(event.pid.value_or(0));
    key.platform_key = event.platform_process_key;
    if (!key.platform_key) key.start_time_ns = event.process_start_time_ns;
    return key;
}

std::string optional_number(const std::optional<std::uint32_t>& value) {
    return value ? std::to_string(*value) : "-";
}

std::string optional_bool(const std::optional<bool>& value) {
    if (!value) return "-";
    return *value ? "yes" : "no";
}

std::string value_or_dash(const std::string& value) {
    return value.empty() ? "-" : value;
}

std::string stable_id(const ProcessInstanceKey& key) {
    if (key.platform_key) return "native:" + std::to_string(*key.platform_key);
    if (key.start_time_ns) return "start-ns:" + std::to_string(*key.start_time_ns);
    return "unstable";
}

ProcessGraph current_graph() {
    ProcessGraph graph;
    for (const auto& event : platform::snapshot_processes()) {
        static_cast<void>(graph.observe(event));
    }
    return graph;
}

void print_node_details(const ProcessNode& node, const std::vector<ProcessNode>& all) {
    std::cout << "PROCESS INSTANCE\n"
              << "PID        " << node.key.pid << '\n'
              << "IDENTITY   " << stable_id(node.key) << '\n'
              << "STATE      " << (node.exited_at_ns ? "exited" : "running") << '\n'
              << "USER       " << value_or_dash(node.user_identity) << '\n'
              << "UID        " << optional_number(node.uid) << '\n'
              << "GID        " << optional_number(node.gid) << '\n'
              << "SESSION    " << optional_number(node.session_id) << '\n'
              << "INTEGRITY  " << value_or_dash(node.integrity_level) << '\n'
              << "ELEVATED   " << optional_bool(node.elevated) << '\n'
              << "IMAGE      " << value_or_dash(node.executable_path) << '\n'
              << "COMMAND    " << value_or_dash(node.command_line) << '\n'
              << "CWD        " << value_or_dash(node.working_directory) << '\n';

    std::cout << "\nPARENT\n";
    if (node.parent) {
        const auto parent = std::find_if(all.begin(), all.end(), [&](const ProcessNode& candidate) {
            return candidate.key == *node.parent;
        });
        std::cout << "PID        " << node.parent->pid << '\n'
                  << "IDENTITY   " << stable_id(*node.parent) << '\n'
                  << "IMAGE      " << (parent == all.end() ? "-" : value_or_dash(parent->executable_path)) << '\n';
    } else if (node.parent_pid) {
        std::cout << "PID        " << *node.parent_pid << "\nIDENTITY   unresolved\nIMAGE      -\n";
    } else {
        std::cout << "-\n";
    }

    std::cout << "\nCHILDREN\n";
    bool any = false;
    for (const auto& candidate : all) {
        if (!candidate.parent || *candidate.parent != node.key) continue;
        any = true;
        std::cout << candidate.key.pid << "  " << value_or_dash(candidate.comm)
                  << "  " << value_or_dash(candidate.executable_path) << '\n';
    }
    if (!any) std::cout << "-\n";
}

void print_tree(const ProcessNode& node,
                const std::unordered_map<ProcessInstanceKey, std::vector<ProcessNode>,
                                         ProcessInstanceKeyHash>& children,
                std::unordered_set<ProcessInstanceKey, ProcessInstanceKeyHash>& visited,
                std::size_t depth) {
    if (!visited.insert(node.key).second) return;
    for (std::size_t i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << (depth == 0 ? "" : "|- ") << node.key.pid << ' '
              << value_or_dash(node.comm);
    if (!node.user_identity.empty()) std::cout << " [" << node.user_identity << ']';
    if (!node.executable_path.empty() && node.executable_path != node.comm) {
        std::cout << "  " << node.executable_path;
    }
    std::cout << '\n';

    const auto found = children.find(node.key);
    if (found == children.end()) return;
    for (const auto& child : found->second) print_tree(child, children, visited, depth + 1);
}

int show_command(int argc, char** argv) {
    if (argc < 4) throw std::runtime_error("usage: neta-agent process show <pid>");
    std::int64_t pid = 0;
    try {
        pid = std::stoll(argv[3]);
    } catch (...) {
        throw std::runtime_error("process show requires a numeric PID");
    }
    if (pid <= 0) throw std::runtime_error("process show requires a positive PID");

    auto graph = current_graph();
    const auto nodes = graph.snapshot();
    const ProcessNode* match = nullptr;
    for (const auto& node : nodes) {
        if (node.key.pid != pid || node.exited_at_ns) continue;
        if (match != nullptr) {
            throw std::runtime_error("multiple active process instances share this PID; refusing ambiguous show");
        }
        match = &node;
    }
    if (match == nullptr) {
        std::cerr << "No running process with PID " << pid
                  << " was visible in the current process snapshot.\n";
        return 2;
    }
    print_node_details(*match, nodes);
    return 0;
}

int graph_command() {
    auto graph = current_graph();
    const auto nodes = graph.snapshot();
    std::unordered_map<ProcessInstanceKey, std::vector<ProcessNode>, ProcessInstanceKeyHash> children;
    std::unordered_set<ProcessInstanceKey, ProcessInstanceKeyHash> known;
    for (const auto& node : nodes) known.insert(node.key);
    for (const auto& node : nodes) {
        if (node.parent && known.contains(*node.parent)) children[*node.parent].push_back(node);
    }

    std::cout << "Process graph: " << nodes.size() << " visible process instance(s)\n";
    std::unordered_set<ProcessInstanceKey, ProcessInstanceKeyHash> visited;
    for (const auto& node : nodes) {
        if (!node.parent || !known.contains(*node.parent)) {
            print_tree(node, children, visited, 0);
        }
    }
    for (const auto& node : nodes) {
        if (!visited.contains(node.key)) print_tree(node, children, visited, 0);
    }

    const auto& health = graph.health();
    if (health.rejected_without_stable_identity != 0 || health.ambiguous_parent_links != 0) {
        std::cout << "Graph health: rejected=" << health.rejected_without_stable_identity
                  << " ambiguous-parent=" << health.ambiguous_parent_links << '\n';
    }
    return 0;
}

int watch_command() {
    ProcessSignalHandlers signals;
    auto observer = platform::make_process_exec_observer();
    const auto& capability = observer->capability();
    if (!capability.available()) {
        throw std::runtime_error("process event collection unavailable: " + capability.unavailable_reason);
    }

    ProcessGraph graph;
    for (const auto& event : platform::snapshot_processes()) {
        static_cast<void>(graph.observe(event));
    }

    std::cout << "Watching process events from " << value_or_dash(capability.source)
              << ". Press Ctrl-C to stop.\n";
    while (process_stop_requested == 0) {
        for (const auto& event : observer->poll(std::chrono::milliseconds(250))) {
            const auto key = event_key(event);
            const auto parent_before = event.parent_tgid
                ? std::optional<std::int64_t>{*event.parent_tgid} : std::nullopt;
            static_cast<void>(graph.observe(event));

            std::cout << (event.type == ProcessExecEventType::Start ? "START " : "EXIT  ")
                      << key.pid << ' ' << value_or_dash(event.comm);
            if (parent_before) std::cout << " <- " << *parent_before;
            if (!event.user_identity.empty()) std::cout << " [" << event.user_identity << ']';
            if (!event.executable_path.empty()) std::cout << "  " << event.executable_path;
            if (!event.command_line.empty()) std::cout << "  cmd=" << event.command_line;
            if (event.type == ProcessExecEventType::Exit && event.exit_code) {
                std::cout << "  code=" << *event.exit_code;
            }
            std::cout << '\n';
        }
    }

    const auto health = observer->health();
    std::cout << "Stopped. Active=" << graph.active_count()
              << " retained=" << graph.snapshot().size()
              << " dropped=" << (health.dropped_events ? std::to_string(*health.dropped_events) : "-")
              << '\n';
    return 0;
}

void print_process_help() {
    std::cout << "Process / MS5:\n"
              << "  neta-agent process watch\n"
              << "      Stream process START/EXIT evidence until Ctrl-C.\n"
              << "  neta-agent process show <pid>\n"
              << "      Show the current process instance, identity, parent and children.\n"
              << "  neta-agent process graph\n"
              << "      Print the current best-effort endpoint process tree.\n";
}

}  // namespace

int run_process_command(int argc, char** argv) {
    if (argc < 3 || std::string(argv[2]) == "help" || std::string(argv[2]) == "--help") {
        print_process_help();
        return argc < 3 ? 1 : 0;
    }
    const std::string command = argv[2];
    if (command == "watch") return watch_command();
    if (command == "show") return show_command(argc, argv);
    if (command == "graph") return graph_command();
    throw std::runtime_error("unknown process command: " + command);
}

}  // namespace neta::cli
