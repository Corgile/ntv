//
// Created by brian on 2025 Jan 31.
//

#ifndef PARSE_OPTION_HH
#define PARSE_OPTION_HH
#include <chrono>
#include <string>
#include <utility>

using namespace std::chrono_literals;
struct ParseOption {
  std::string filter{ "ip or vlan" };
  decltype(10ms) timeout{ 10s };

  ParseOption() = default;
  ParseOption(std::string filter, int64_t const timeout)
      : filter{ std::move(filter) }
      , timeout{ timeout } {}

  ParseOption(ParseOption const& other)            = default;
  ParseOption& operator=(ParseOption const& other) = default;

  ParseOption(ParseOption&& other) noexcept
      : filter{ std::move(other.filter) }
      , timeout{ other.timeout } {}

  ParseOption& operator=(ParseOption&& other) noexcept {
    if (this == &other) return *this;
    filter  = std::move(other.filter);
    timeout = other.timeout;
    return *this;
  }
};

#endif // PARSE_OPTION_HH
