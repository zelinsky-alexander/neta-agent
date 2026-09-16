#include "neta/outbound_dispatcher.hpp"

#include "neta/fleet_client.hpp"
#include "neta/nap_sequence.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace neta {
namespace {

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;
constexpr std::uint64_t kAttemptLifetimeNs = 300ULL * kNanosecondsPerSecond;
constexpr std::uint64_t kAttemptRefreshMarginNs = 5ULL * kNanosecondsPerSecond;

std::uint64_t system_now_ns() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string random_uuid() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        throw std::runtime_error("random NAP message ID generation failed");
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
    char output[37];
    std::snprintf(output, sizeof(output),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                  bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return output;
}

std::string iso8601(std::uint64_t nanoseconds) {
    const auto milliseconds = nanoseconds / 1'000'000ULL;
    const std::time_t seconds = static_cast<std::time_t>(milliseconds / 1000ULL);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &seconds);
#else
    gmtime_r(&seconds, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.'
           << std::setw(3) << std::setfill('0') << (milliseconds % 1000ULL) << 'Z';
    return output.str();
}

std::string json_escape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20U)
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(character) << std::dec;
                else
                    output << static_cast<char>(character);
        }
    }
    return output.str();
}

std::uint64_t retry_delay_ns(const OutboundMessage& message) {
    const auto exponent = std::min<std::uint64_t>(message.attempt_count, 6);
    const auto seconds = std::min<std::uint64_t>(300, 5ULL << exponent);
    const auto jitter = message.event_counter % 5ULL;
    return (seconds + jitter) * kNanosecondsPerSecond;
}

bool is_permanent_rejection(const FleetHttpError& error) {
    if (error.status_code() == 413 || error.status_code() == 422) return true;
    if (error.status_code() == 409)
        return error.response_body().find("different content") != std::string::npos;
    if (error.status_code() != 400) return false;
    const auto& body = error.response_body();
    return body.find("expired") == std::string::npos &&
           body.find("clock") == std::string::npos &&
           body.find("created_at is too far") == std::string::npos;
}

}  // namespace

OutboundDispatcher::OutboundDispatcher(OutboundQueue& queue, std::filesystem::path state_dir)
    : queue_(queue), state_dir_(std::move(state_dir)) {}

OutboundMessage OutboundDispatcher::prepare_attempt(OutboundMessage message,
                                                     std::uint64_t now_ns) const {
    if (!message.attempt_envelope_json.empty() &&
        message.attempt_expires_at_ns > now_ns + kAttemptRefreshMarginNs) {
        return message;
    }

    const FleetIdentity identity = FleetClient::load_identity(state_dir_);
    message.attempt_message_id = random_uuid();
    message.attempt_sequence = next_nap_sequence(state_dir_);
    message.attempt_expires_at_ns = now_ns + kAttemptLifetimeNs;
    std::ostringstream envelope;
    envelope << '{'
             << "\"protocol\":\"neta-agent/1\","
             << "\"schema_version\":1,"
             << "\"message_id\":\"" << message.attempt_message_id << "\","
             << "\"message_type\":\"" << json_escape(message.message_type) << "\","
             << "\"agent_id\":\"" << json_escape(identity.agent_id) << "\","
             << "\"created_at\":\"" << iso8601(now_ns) << "\","
             << "\"expires_at\":\"" << iso8601(message.attempt_expires_at_ns) << "\","
             << "\"sequence\":" << message.attempt_sequence << ','
             << "\"correlation_id\":null,"
             << "\"idempotency_key\":\"" << json_escape(message.event_id) << "\","
             << "\"payload_hash\":\"" << message.payload_hash << "\","
             << "\"payload\":" << message.payload_json << ','
             << "\"signature\":{"
             << "\"algorithm\":\"UNSIGNED-NAP1-DRAFT\","
             << "\"key_id\":\"" << json_escape(identity.certificate_sha256) << "\","
             << "\"value\":\"transport-mtls-only\"}}";
    message.attempt_envelope_json = envelope.str();
    queue_.store_attempt(message, now_ns);
    return message;
}

OutboundDispatchResult OutboundDispatcher::drain(std::size_t maximum_messages) {
    OutboundDispatchResult result;
    const auto initial_now_ns = system_now_ns();
    constexpr std::uint64_t acknowledged_retention_ns =
        24ULL * 60ULL * 60ULL * kNanosecondsPerSecond;
    queue_.prune_acknowledged(
        initial_now_ns > acknowledged_retention_ns
            ? initial_now_ns - acknowledged_retention_ns
            : 0);
    try {
        queue_.enqueue_gap_marker(initial_now_ns);
    } catch (const std::exception&) {
        // A full queue may temporarily have no room for the marker. The durable
        // dropped counter causes a later drain to try again after capacity clears.
    }
    while (result.attempted < maximum_messages) {
        const auto now_ns = system_now_ns();
        auto ready = queue_.next_ready(now_ns);
        if (!ready) break;
        ++result.attempted;
        try {
            const auto message = prepare_attempt(*ready, now_ns);
            const auto response = FleetClient::post_nap_envelope(
                state_dir_, message.attempt_envelope_json);
            const auto ack = parse_coordinator_ack(response);
            validate_coordinator_ack(ack, message.attempt_message_id,
                                     message.attempt_sequence, message.event_id,
                                     message.payload_hash);
            queue_.mark_acknowledged(message.event_id, ack, system_now_ns());
            ++result.acknowledged;
        } catch (const FleetHttpError& error) {
            if (is_permanent_rejection(error)) {
                queue_.mark_dead_letter(ready->event_id, error.what());
            } else {
                queue_.mark_retry(
                    ready->event_id, now_ns + retry_delay_ns(*ready), error.what());
            }
            ++result.failed;
            break;
        } catch (const std::exception& error) {
            queue_.mark_retry(ready->event_id, now_ns + retry_delay_ns(*ready), error.what());
            ++result.failed;
            break;
        }
    }
    return result;
}

}  // namespace neta
