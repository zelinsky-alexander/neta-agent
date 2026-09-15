#include "neta/platform.hpp"
#include "neta/windows_sensor_broker.hpp"
#include "sensor_broker_native.hpp"

#ifdef _WIN32

namespace neta::platform {

std::unique_ptr<LifecycleObserver> make_lifecycle_observer() {
    if (windows_sensor_broker::broker_mode_requested()) {
        return windows_sensor_broker::make_broker_lifecycle_observer();
    }
    return make_native_windows_lifecycle_observer();
}

std::unique_ptr<ProcessExecObserver> make_process_exec_observer() {
    if (windows_sensor_broker::broker_mode_requested()) {
        return windows_sensor_broker::make_broker_process_exec_observer();
    }
    return make_native_windows_process_exec_observer();
}

std::unique_ptr<NameResolutionObserver> make_name_resolution_observer() {
    if (windows_sensor_broker::broker_mode_requested()) {
        return windows_sensor_broker::make_broker_name_resolution_observer();
    }
    return make_native_windows_name_resolution_observer();
}

std::unique_ptr<TlsSessionObserver> make_tls_session_observer() {
    if (windows_sensor_broker::broker_mode_requested()) {
        return windows_sensor_broker::make_broker_tls_session_observer();
    }
    return make_native_windows_tls_session_observer_factory();
}

}  // namespace neta::platform

#endif
