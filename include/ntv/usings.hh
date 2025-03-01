//
// Created by brian on 2025 Feb 01.
//

#ifndef USINGS_HH
#define USINGS_HH
#include <list>
#include <map>
#include <memory>
#include <moodycamel/concurrent_queue.hh>

struct RawPacket;
using raw_packet_t   = std::shared_ptr<RawPacket>;
using packet_queue_t = moodycamel::ConcurrentQueue<raw_packet_t>;
using packet_list_t  = std::list<raw_packet_t>;
using ustring_t      = std::basic_string<u_char>;
using ustring_view   = std::basic_string_view<u_char>;
using flow_node_t    = std::map<std::string, packet_list_t>::node_type;

#endif // USINGS_HH
