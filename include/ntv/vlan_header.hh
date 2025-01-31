//
// Created by brian on 11/28/23.
//

#ifndef VLAN_HEADER_HPP
#define VLAN_HEADER_HPP

#include <cstdint>

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
  /** Ethernet type for next layer */
  uint16_t etherType;
} __attribute__((__packed__));

#endif // VLAN_HEADER_HPP
