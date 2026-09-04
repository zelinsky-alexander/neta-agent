#pragma once

namespace neta::cli {

void run_observation_command(int argc, char** argv, bool service_mode);
void request_observation_stop() noexcept;

} // namespace neta::cli
