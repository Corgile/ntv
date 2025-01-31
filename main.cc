#include <iostream>
#include <ntv/pcap_parser.hh>

int main() {
  PcapParser parser{};
  parser.ParseFile("/data/Projects/dataset/TCP_IP-DDoS-UDP1_train.pcap");
  return 0;
}
