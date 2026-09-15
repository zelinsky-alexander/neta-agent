#pragma once

#ifdef _WIN32

#include "neta/lifecycle.hpp"
#include "neta/name_resolution.hpp"
#include "neta/process_exec.hpp"
#include "neta/tls_session.hpp"

#include <memory>

namespace neta::platform {

std::unique_ptr<LifecycleObserver> make_native_windows_lifecycle_observer();
std::unique_ptr<ProcessExecObserver> make_native_windows_process_exec_observer();
std::unique_ptr<NameResolutionObserver> make_native_windows_name_resolution_observer();
std::unique_ptr<TlsSessionObserver> make_native_windows_tls_session_observer_factory();

}  // namespace neta::platform

#endif
