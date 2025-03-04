#ifndef NTV_GLOBALS_HH
#define NTV_GLOBALS_HH
#include <ntv/globals.hh>
#include <ntv/parse_option.hh>

#include <semaphore>
namespace global {
extern ParseOption opt;
extern std::counting_semaphore<1024> fileSemaphore;
} // namespace global
#endif
