//
// Created by corgi on 2025 四月 02.
//

#pragma once
#include <ntv/raw_packet.hh>
#include <ntv/usings.hh>
#include <opencv2/opencv.hpp>

class GAF {
public:
  explicit GAF(const packet_list_t& packets, int target_len = 64);
  [[nodiscard]] cv::Mat getMatrix() const;

private:
  static std::vector<float> extractTimeSeries(const packet_list_t& packets, int len);
  static cv::Mat computeGAF(const std::vector<float>& series);
  cv::Mat matrix_;
};