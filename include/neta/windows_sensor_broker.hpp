#pragma once

#ifdef _WIN32

#include "neta/lifecycle.hpp"
#include "neta/name_resolution.hpp"
#include "neta/process_exec.hpp"
#include "neta/tls_session.hpp"

#include <memory>
#include <string>

namespace neta::windows_sensor_broker {

bool broker_mode_requested();
std::wstring configured_pipe_name();
std::string configured_endpoint_slot();

std::unique_ptr<LifecycleObserver> make_broker_lifecycle_observer();
std::unique_ptr<ProcessExecObserver> make_broker_process_exec_observer();
std::unique_ptr<NameResolutionObserver> make_broker_name_resolution_observer();
std::unique_ptr<TlsSessionObserver> make_broker_tls_session_observer();

int run_windows_sensor_broker(int argc, char** argv);

}  // namespace neta::windows_sensor_broker

#endif
