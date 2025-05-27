//
// Created by corgi on 2025-05-28.
//

#include <ntv/flow_key.hh>

void to_json(nlohmann::json& j, const FlowKey& fk) {
  j = nlohmann::json{ { "ip1", fk.ip1 },
                      { "ip2", fk.ip2 },
                      { "port1", fk.port1 },
                      { "port2", fk.port2 },
                      { "protocol", fk.protocol } };
}
