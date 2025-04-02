//
// Created by brian on 2025 Feb 01.
//

#ifndef USINGS_HH
#define USINGS_HH
#include <list>
#include <memory>
#include <moodycamel/concurrent_queue.hh>
#include <vector>

struct FlowKey;
struct RawPacket;
using raw_packet_t   = std::shared_ptr<RawPacket>;
using packet_queue_t = moodycamel::ConcurrentQueue<raw_packet_t>;
using packet_list_t  = std::list<raw_packet_t>;
using ustring_t    = std::vector<u_char>;
using ustring_view = std::basic_string_view<u_char>;

using raw_packet_t  = std::shared_ptr<RawPacket>;
using packet_list_t = std::list<raw_packet_t>;
using flow_node_t   = std::pair<FlowKey, packet_list_t>;

#endif // USINGS_HH
