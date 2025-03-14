//
// Created by corgi on 2025 Mar 01.
//

#ifndef MISSING_HH
#define MISSING_HH

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define ETH_ALEN 6
// 定义以太网类型宏
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IPV6 0x86DD
// 定义 IP 协议类型
#define IS_LITTLE_ENDIAN 1
#define IS_BIG_ENDIAN 0

#pragma pack(push, 1)

#ifndef NTV_ETH_HDR_DEF
#define NTV_ETH_HDR_DEF
/* Ethernet 头结构定义 */
typedef struct ether_header {
  unsigned char h_dest[ETH_ALEN];   // 目的 MAC 地址
  unsigned char h_source[ETH_ALEN]; // 源 MAC 地址
  uint16_t ether_type;              // 上层协议类型（网络字节序）
} ethhdr;
#endif // NTV_ETH_HDR_DEF

/* IP 头结构定义 */
#ifndef NTV_IP_HDR_DEF
#define NTV_IP_HDR_DEF
typedef struct ip {
#if IS_LITTLE_ENDIAN
  uint8_t ip_hl : 4;   // IP 首部长度
  uint8_t version : 4; // 版本号
#elif IS_BIG_ENDIAN
  uint8_t version : 4;
  uint8_t ihl : 4;
#else
#error "请定义 IS_LITTLE_ENDIAN 或 IS_BIG_ENDIAN"
#endif
  uint8_t tos;       // 服务类型
  uint16_t tot_len;  // 总长度
  uint16_t id;       // 标识
  uint16_t frag_off; // 分片偏移
  uint8_t ttl;       // 生存时间
  uint8_t ip_p;      // 协议
  uint16_t check;    // 首部校验和
  in_addr ip_src;    // 源 IP 地址
  in_addr ip_dst;    // 目的 IP 地址
  // 可选字段（如果存在）紧跟其后
} iphdr;
#endif // NTV_IP_HDR_DEF

#ifndef NTV_TCP_HDR_DEF
#define NTV_TCP_HDR_DEF
/* TCP 头结构定义 */
typedef struct tcphdr {
  uint16_t th_sport; // 源端口
  uint16_t th_dport; // 目的端口
  uint32_t seq;      // 序列号
  uint32_t ack_seq;  // 确认号
#if defined(IS_LITTLE_ENDIAN)
  uint16_t res1 : 4, // 保留
    doff : 4,        // TCP 首部长度
    fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined(IS_BIG_ENDIAN)
  uint16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1,
    rst : 1, syn : 1, fin : 1;
#else
#error "请定义 IS_LITTLE_ENDIAN 或 IS_BIG_ENDIAN"
#endif
  uint16_t window;  // 窗口大小
  uint16_t check;   // 校验和
  uint16_t urg_ptr; // 紧急指针
} tcphdr;
#endif // NTV_TCP_HDR_DEF

#ifndef NTV_UDP_HDR_DEF
#define NTV_UDP_HDR_DEF
/* UDP 头结构定义 */
typedef struct udphdr {
  uint16_t uh_sport; // 源端口
  uint16_t uh_dport; // 目的端口
  uint16_t len;      // UDP 长度
  uint16_t check;    // 校验和
} udphdr;
#endif // NTV_UDP_HDR_DEF

#pragma pack(pop)

#else
#include <netinet/in.h>
#endif

#endif
