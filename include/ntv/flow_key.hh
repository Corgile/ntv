//
// Created by corgi on 2025 四月 01.
//

#ifndef FLOW_KEY_HH
#define FLOW_KEY_HH

#include <cstdint>
#include <functional>
#include <nlohmann/json.hpp>

struct FlowKey {
  uint32_t ip1;
  uint32_t ip2;
  uint16_t port1;
  uint16_t port2;
  uint8_t protocol;

  bool operator==(const FlowKey&) const = default;
};
void to_json(nlohmann::json& j, const FlowKey& fk);

template <>
struct std::hash<FlowKey> {
  inline size_t operator()(FlowKey const& k) const noexcept {
    return static_cast<size_t>(k.ip1) << 32 ^ k.ip2 ^
      (static_cast<size_t>(k.port1) << 16 ^ k.port2) ^ k.protocol;
  }
};

#endif // FLOW_KEY_HH
