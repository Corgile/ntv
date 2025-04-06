//
// Created by corgi on 2025 四月 06.
//

#include <algorithm>
#include <ntv/aligned_packet.hh>

bool AlignedPacket::Empty() const {
  bool all_zero =
    std::all_of(bytes.begin(), bytes.end(), [](u_char c) { return c == 0; });
  return all_zero && key == FlowKey{ 0, 0, 0, 0, 0 };
}
size_t AlignedPacket::Size() const { return 192; }
const u_char* AlignedPacket::Data() const { return bytes.data(); }
