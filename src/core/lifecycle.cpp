#include "neta/lifecycle.hpp"

namespace neta {

std::string to_string(ConnectionLifecycleEventType value) {
    switch (value) {
        case ConnectionLifecycleEventType::Connect: return "CONNECT";
        case ConnectionLifecycleEventType::Accept: return "ACCEPT";
        case ConnectionLifecycleEventType::Close: return "CLOSE";
    }
    return "UNKNOWN";
}

std::string to_string(LifecycleProvenance value) {
    switch (value) {
        case LifecycleProvenance::EbpfCore: return "EBPF_CORE";
        case LifecycleProvenance::DeterministicTest: return "DETERMINISTIC_TEST";
    }
    return "UNKNOWN";
}

} // namespace neta
