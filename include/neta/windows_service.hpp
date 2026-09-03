#pragma once

namespace neta::platform {

// Enter the Windows Service Control Manager dispatcher for the NETAAgent
// service. argv uses the normal neta-agent process command line, with
// "service" at argv[1] and observation options following it.
int run_windows_service(int argc, char** argv);

} // namespace neta::platform
