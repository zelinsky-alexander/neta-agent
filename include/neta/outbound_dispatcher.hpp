#pragma once

#include "neta/outbound_queue.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace neta {

struct OutboundDispatchResult {
    std::size_t attempted{0};
    std::size_t acknowledged{0};
    std::size_t failed{0};
};

class OutboundDispatcher {
public:
    OutboundDispatcher(OutboundQueue& queue, std::filesystem::path state_dir);
    [[nodiscard]] OutboundDispatchResult drain(std::size_t maximum_messages);

private:
    [[nodiscard]] OutboundMessage prepare_attempt(OutboundMessage message,
                                                  std::uint64_t now_ns) const;

    OutboundQueue& queue_;
    std::filesystem::path state_dir_;
};

}  // namespace neta
