//
// Created by corgi on 2025 四月 02.
//

#include <cmath>
#include <ntv/gaf.hh>

GAF::GAF(const packet_list_t& packets, int target_len) {
  std::vector<float> series = extractTimeSeries(packets, target_len);
  matrix_                   = computeGAF(series);
}

cv::Mat GAF::getMatrix() const {
  cv::Mat img;
  matrix_.convertTo(img, CV_8UC1, 255.0);
  return img;
}

std::vector<float> GAF::extractTimeSeries(const packet_list_t& packets,
                                          int len) {
  std::vector<uchar> bytes;
  for (const auto& pkt : packets) {
    if (!pkt) continue;
    bytes.insert(bytes.end(), pkt->byte_arr.begin(), pkt->byte_arr.end());
  }

  // 截断/填充
  bytes.resize(len, 0);

  // 归一化到 [0, 1]
  std::vector<float> series(len);
  for (int i = 0; i < len; ++i) {
    series[i] = static_cast<float>(bytes[i]) / 255.0f;
  }

  return series;
}

cv::Mat GAF::computeGAF(const std::vector<float>& series) {
  int len = static_cast<int>(series.size());
  cv::Mat gaf(len, len, CV_32FC1);

  std::vector<float> phi(len);
  for (int i = 0; i < len; ++i) {
    phi[i] = std::acos(series[i]); // arccos(x) ∈ [0, pi]
  }

  for (int i = 0; i < len; ++i) {
    for (int j = 0; j < len; ++j) {
      gaf.at<float>(i, j) = std::cos(phi[i] + phi[j]); // GASF
    }
  }

  return gaf;
}
