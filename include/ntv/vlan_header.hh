//
// Created by brian on 11/28/23.
//

#ifndef VLAN_HEADER_HPP
#define VLAN_HEADER_HPP

#include <cstdint>

#ifdef WIN32
#pragma pack(push, 1)
#endif

struct vlan_header {
  /**
   * @verbatim
   * 0                 1
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |Prio |C|         VLAN ID     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * @endverbatim
   */
  uint16_t vlan;
  uint16_t etherType;
}
#ifndef WIN32
__attribute__((__packed__));
#else
;
#pragma pack(pop)
#endif

#endif // VLAN_HEADER_HPP
