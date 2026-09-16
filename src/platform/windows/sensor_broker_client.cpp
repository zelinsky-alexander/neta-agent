#include "neta/windows_sensor_broker.hpp"
#include "sensor_broker_pipe.hpp"
#include "sensor_broker_protocol.hpp"

#ifdef _WIN32

#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace neta::windows_sensor_broker {
namespace {

class BrokerConnection {
public:
    BrokerConnection(std::wstring pipe_name, std::string slot)
        : pipe_(connect_named_pipe_client(pipe_name, std::chrono::seconds(5))) {
        const auto registration = protocol::encode_registration(protocol::Registration{slot});
        if (!write_pipe_message(pipe_, registration)) {
            close_pipe(pipe_);
            throw std::runtime_error("registering with Windows sensor broker failed");
        }
        worker_ = std::thread([this] { read_loop(); });
    }

    ~BrokerConnection() {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        close_pipe(pipe_);
        condition_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    BrokerConnection(const BrokerConnection&) = delete;
    BrokerConnection& operator=(const BrokerConnection&) = delete;

    std::vector<ConnectionLifecycleEvent> poll_lifecycle(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (lifecycle_.empty() && !failed_ && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] {
                return !lifecycle_.empty() || failed_ || stopping_;
            });
        }
        throw_if_failed();
        std::vector<ConnectionLifecycleEvent> result;
        result.reserve(lifecycle_.size());
        while (!lifecycle_.empty()) {
            result.push_back(std::move(lifecycle_.front()));
            lifecycle_.pop_front();
        }
        return result;
    }

    std::vector<ProcessExecEvent> poll_process(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (process_.empty() && !failed_ && timeout.count() > 0) {
            condition_.wait_for(lock, timeout, [this] {
                return !process_.empty() || failed_ || stopping_;
            });
        }
        throw_if_failed();
        std::vector<ProcessExecEvent> result;
        result.reserve(process_.size());
        while (!process_.empty()) {
            result.push_back(std::move(process_.front()));
            process_.pop_front();
        }
        return result;
    }

private:
    void throw_if_failed() const {
        if (failed_) throw std::runtime_error(failure_message_);
    }

    void fail(std::string message) {
        {
            std::lock_guard lock(mutex_);
            if (failed_) return;
            failed_ = true;
            failure_message_ = std::move(message);
        }
        condition_.notify_all();
    }

    void read_loop() noexcept {
        try {
            for (;;) {
                {
                    std::lock_guard lock(mutex_);
                    if (stopping_) return;
                }
                const auto frame = read_pipe_message(pipe_, std::chrono::milliseconds(250));
                if (!frame) continue;
                const auto type = protocol::message_type(*frame);
                if (!type) {
                    fail("Windows sensor broker sent an invalid frame");
                    return;
                }
                if (*type == protocol::MessageType::Lifecycle) {
                    auto event = protocol::decode_lifecycle(*frame);
                    if (!event) {
                        fail("Windows sensor broker sent an invalid lifecycle frame");
                        return;
                    }
                    {
                        std::lock_guard lock(mutex_);
                        lifecycle_.push_back(std::move(*event));
                    }
                    condition_.notify_all();
                } else if (*type == protocol::MessageType::ProcessExec) {
                    auto event = protocol::decode_process_exec(*frame);
                    if (!event) {
                        fail("Windows sensor broker sent an invalid process frame");
                        return;
                    }
                    {
                        std::lock_guard lock(mutex_);
                        process_.push_back(std::move(*event));
                    }
                    condition_.notify_all();
                }
            }
        } catch (const std::exception& error) {
            bool stopping = false;
            {
                std::lock_guard lock(mutex_);
                stopping = stopping_;
            }
            if (!stopping) fail(std::string("Windows sensor-broker connection failed: ") + error.what());
        }
    }

    HANDLE pipe_{INVALID_HANDLE_VALUE};
    std::thread worker_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<ConnectionLifecycleEvent> lifecycle_;
    std::deque<ProcessExecEvent> process_;
    bool stopping_{false};
    bool failed_{false};
    std::string failure_message_;
};

std::shared_ptr<BrokerConnection> shared_connection() {
    static std::mutex mutex;
    static std::weak_ptr<BrokerConnection> weak;
    std::lock_guard lock(mutex);
    if (auto existing = weak.lock()) return existing;
    auto created = std::make_shared<BrokerConnection>(configured_pipe_name(), configured_endpoint_slot());
    weak = created;
    return created;
}

class BrokerLifecycleObserver final : public LifecycleObserver {
public:
    BrokerLifecycleObserver() {
        capability_.built_in = true;
        capability_.source = "broker:windows-etw-lifecycle";
        try {
            connection_ = shared_connection();
            capability_.connect_events = true;
            capability_.accept_events = true;
            capability_.close_events = true;
        } catch (const std::exception& error) {
            capability_.unavailable_reason = error.what();
        }
    }

    const LifecycleCapability& capability() const noexcept override { return capability_; }
    LifecycleHealth health() const override { return {}; }

    std::vector<ConnectionLifecycleEvent> poll(std::chrono::milliseconds timeout) override {
        if (!connection_) return {};
        return connection_->poll_lifecycle(timeout);
    }

private:
    LifecycleCapability capability_;
    std::shared_ptr<BrokerConnection> connection_;
};

class BrokerProcessExecObserver final : public ProcessExecObserver {
public:
    BrokerProcessExecObserver() {
        capability_.built_in = true;
        capability_.source = "broker:windows-etw-process";
        try {
            connection_ = shared_connection();
            capability_.exec_events = true;
            capability_.exit_events = true;
            capability_.parent_identity = true;
            capability_.command_line = true;
            capability_.working_directory = true;
            capability_.security_identity = true;
            capability_.session_identity = true;
        } catch (const std::exception& error) {
            capability_.unavailable_reason = error.what();
        }
    }

    const ProcessExecCapability& capability() const noexcept override { return capability_; }
    ProcessExecHealth health() const override { return {}; }

    std::vector<ProcessExecEvent> poll(std::chrono::milliseconds timeout) override {
        if (!connection_) return {};
        return connection_->poll_process(timeout);
    }

private:
    ProcessExecCapability capability_;
    std::shared_ptr<BrokerConnection> connection_;
};

}  // namespace

std::unique_ptr<LifecycleObserver> make_broker_lifecycle_observer() {
    return std::make_unique<BrokerLifecycleObserver>();
}

std::unique_ptr<ProcessExecObserver> make_broker_process_exec_observer() {
    return std::make_unique<BrokerProcessExecObserver>();
}

}  // namespace neta::windows_sensor_broker

#endif
