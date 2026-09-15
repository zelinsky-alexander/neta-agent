#include "sensor_broker_router.hpp"
#include "sensor_broker_protocol.hpp"

#ifdef _WIN32

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace neta::windows_sensor_broker {
namespace {

class BoundedFrameQueue {
public:
    explicit BoundedFrameQueue(std::size_t capacity) : capacity_(capacity) {
        if (capacity_ == 0) throw std::runtime_error("Windows sensor-broker queue capacity must be positive");
    }

    void push(std::vector<std::byte> frame) {
        {
            std::lock_guard lock(mutex_);
            if (frames_.size() >= capacity_) {
                frames_.pop_front();
                ++dropped_;
            }
            frames_.push_back(std::move(frame));
        }
        condition_.notify_one();
    }

    std::optional<std::vector<std::byte>> take(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (frames_.empty() && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] { return !frames_.empty(); });
        }
        if (frames_.empty()) return std::nullopt;
        auto frame = std::move(frames_.front());
        frames_.pop_front();
        return frame;
    }

    std::uint64_t dropped() const {
        std::lock_guard lock(mutex_);
        return dropped_;
    }

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::vector<std::byte>> frames_;
    std::uint64_t dropped_{0};
};

}  // namespace

class BrokerEventRouter::Impl {
public:
    explicit Impl(std::size_t queue_capacity) : queue_capacity_(queue_capacity) {
        if (queue_capacity_ == 0) throw std::runtime_error("Windows sensor-broker queue capacity must be positive");
    }

    void register_endpoint(const std::string& slot) {
        if (slot.empty()) throw std::runtime_error("Windows sensor-broker endpoint slot must not be empty");
        std::lock_guard lock(mutex_);
        queues_.try_emplace(slot, std::make_shared<BoundedFrameQueue>(queue_capacity_));
    }

    bool has_endpoint(const std::string& slot) const {
        std::lock_guard lock(mutex_);
        return queues_.contains(slot);
    }

    bool route(const std::string& slot, std::vector<std::byte> frame) {
        std::shared_ptr<BoundedFrameQueue> queue;
        {
            std::lock_guard lock(mutex_);
            const auto found = queues_.find(slot);
            if (found == queues_.end()) return false;
            queue = found->second;
        }
        queue->push(std::move(frame));
        return true;
    }

    std::optional<std::vector<std::byte>> take(const std::string& slot,
                                                std::chrono::milliseconds timeout) {
        std::shared_ptr<BoundedFrameQueue> queue;
        {
            std::lock_guard lock(mutex_);
            const auto found = queues_.find(slot);
            if (found == queues_.end()) return std::nullopt;
            queue = found->second;
        }
        return queue->take(timeout);
    }

    std::uint64_t dropped(const std::string& slot) const {
        std::shared_ptr<BoundedFrameQueue> queue;
        {
            std::lock_guard lock(mutex_);
            const auto found = queues_.find(slot);
            if (found == queues_.end()) return 0;
            queue = found->second;
        }
        return queue->dropped();
    }

    void note_unroutable() { unroutable_.fetch_add(1, std::memory_order_relaxed); }
    std::uint64_t unroutable() const noexcept { return unroutable_.load(std::memory_order_relaxed); }

private:
    std::size_t queue_capacity_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<BoundedFrameQueue>> queues_;
    std::atomic<std::uint64_t> unroutable_{0};
};

BrokerEventRouter::BrokerEventRouter(std::size_t queue_capacity)
    : impl_(std::make_unique<Impl>(queue_capacity)) {}
BrokerEventRouter::~BrokerEventRouter() = default;
BrokerEventRouter::BrokerEventRouter(BrokerEventRouter&&) noexcept = default;
BrokerEventRouter& BrokerEventRouter::operator=(BrokerEventRouter&&) noexcept = default;

void BrokerEventRouter::register_endpoint(const std::string& slot) { impl_->register_endpoint(slot); }
bool BrokerEventRouter::has_endpoint(const std::string& slot) const { return impl_->has_endpoint(slot); }

bool BrokerEventRouter::route_lifecycle(const std::string& slot,
                                        const ConnectionLifecycleEvent& event,
                                        std::uint64_t sequence) {
    return impl_->route(slot, protocol::encode_lifecycle(event, sequence));
}

bool BrokerEventRouter::route_process_exec(const std::string& slot,
                                           const ProcessExecEvent& event,
                                           std::uint64_t sequence) {
    return impl_->route(slot, protocol::encode_process_exec(event, sequence));
}

std::optional<std::vector<std::byte>> BrokerEventRouter::take(
    const std::string& slot, std::chrono::milliseconds timeout) {
    return impl_->take(slot, timeout);
}

std::uint64_t BrokerEventRouter::dropped(const std::string& slot) const { return impl_->dropped(slot); }
void BrokerEventRouter::note_unroutable() { impl_->note_unroutable(); }
std::uint64_t BrokerEventRouter::unroutable() const noexcept { return impl_->unroutable(); }

}  // namespace neta::windows_sensor_broker

#endif
