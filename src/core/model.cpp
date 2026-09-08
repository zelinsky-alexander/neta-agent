#include "neta/model.hpp"

namespace neta {

std::string to_string(EvidenceFidelity value) {
    switch (value) {
        case EvidenceFidelity::Exact: return "EXACT";
        case EvidenceFidelity::StronglyCorrelated: return "STRONGLY_CORRELATED";
        case EvidenceFidelity::Supporting: return "SUPPORTING";
        case EvidenceFidelity::Contextual: return "CONTEXTUAL";
    }
    return "UNKNOWN";
}

std::string to_string(PerformanceState value) {
    switch (value) {
        case PerformanceState::Normal: return "NORMAL";
        case PerformanceState::Degraded: return "DEGRADED";
        case PerformanceState::Failed: return "FAILED";
        case PerformanceState::InsufficientEvidence: return "INSUFFICIENT_EVIDENCE";
    }
    return "INSUFFICIENT_EVIDENCE";
}

std::string to_string(TrustState value) {
    switch (value) {
        case TrustState::Stable: return "STABLE";
        case TrustState::Changed: return "CHANGED";
        case TrustState::Suspicious: return "SUSPICIOUS";
        case TrustState::Unverified: return "UNVERIFIED";
    }
    return "UNVERIFIED";
}

PerformanceState performance_state_from_string(const std::string& value) {
    if (value == "NORMAL") return PerformanceState::Normal;
    if (value == "DEGRADED") return PerformanceState::Degraded;
    if (value == "FAILED") return PerformanceState::Failed;
    return PerformanceState::InsufficientEvidence;
}

TrustState trust_state_from_string(const std::string& value) {
    if (value == "STABLE") return TrustState::Stable;
    if (value == "CHANGED") return TrustState::Changed;
    if (value == "SUSPICIOUS") return TrustState::Suspicious;
    return TrustState::Unverified;
}

} // namespace neta

// MS5.2 is kept in its own implementation unit for ownership/readability. It is
// included here so existing build manifests remain unchanged across all supported
// flavors; a later build-file cleanup can list it explicitly without changing ABI.
#include "process_finding_store.cpp"
