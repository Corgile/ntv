//
// Created by brian on 2025 Jan 31.
//

#include <ntv/globals.hh>

namespace global {
ParseOption opt{};
// 限制最多同时打开1000个pcap文件(linux上有限制)
std::counting_semaphore<1024> fileSemaphore{ 1000 };
} // namespace global
