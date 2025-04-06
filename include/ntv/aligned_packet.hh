//
// Created by corgi on 2025 四月 06.
//

#ifndef ALIGNED_PACKET_HH
#define ALIGNED_PACKET_HH

#include <array>
#include <ntv/flow_key.hh>

using u_char = unsigned char;

struct AlignedPacket {
  std::array<u_char, 192> bytes;
  FlowKey key;
  [[nodiscard]] bool Empty() const;
  [[nodiscard]] size_t Size() const;
  [[nodiscard]] const u_char* Data() const;
};


#endif //ALIGNED_PACKET_HH
