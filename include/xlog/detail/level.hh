//
// xlog / level.hh
// Created by brian on 2024-06-03.
//

#ifndef XLOG_LEVEL_HH
#define XLOG_LEVEL_HH
#ifdef WIN32
#ifdef ERROR
#undef ERROR
#endif
#endif

namespace xlog {

enum class Level {
  NONE = 0,
  TRACE,
  DEBUG,
  INFO,
  WARN,
  ERROR,
  FATAL,
};

} // namespace xlog

#endif // XLOG_LEVEL_HH
