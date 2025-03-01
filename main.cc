#include <ntv/pcap_parser.hh>
#include <xlog/api.hh>

int main(int const argc, char* argv[]) {
  xlog::setLogLevelTo(xlog::Level::INFO);
  if (argc < 2) {
    XLOG_WARN << "Usage: " << fs::path{ argv[0] }.stem().string()
              << " <pcapfile>";
    exit(EXIT_FAILURE);
  }
  fs::path const pcap_file{ argv[1] };
  XLOG_INFO << "开始: " << pcap_file.string();
  xlog::toggleAsyncLogging(TOGGLE_OFF);
  xlog::toggleConsoleLogging(TOGGLE_ON);
  PcapParser parser{};
  parser.ParseFile(pcap_file);
  return 0;
}
