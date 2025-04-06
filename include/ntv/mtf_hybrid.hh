//
// Created by corgi on 2025 四月 02.
//


#pragma once
#include <ntv/raw_packet.hh>
#include <ntv/usings.hh>
#include <opencv2/opencv.hpp>

class MTFHybrid {
public:
  explicit MTFHybrid(const packet_list_t& packets);

  cv::Mat getMatrix() const;

private:
  static std::vector<int> extractAllTransitions(const packet_list_t& packets);
  static std::vector<cv::Mat> extractLocalMTFs(const packet_list_t& packets, int count);
  static cv::Mat computeMTF(const std::vector<int>& transitions);
  static cv::Mat tileMTFs(const std::vector<cv::Mat>& tiles, int cols, int dim);
  cv::Mat matrix_;
};

