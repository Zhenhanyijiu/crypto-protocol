#ifndef __FU_BLOOM_FILTER_H__
#define __FU_BLOOM_FILTER_H__
#include <bits/stdc++.h>
namespace fucrypto {
class bloom_filter {
 private:
  int _num_hash_func;
  uint32_t _num_bits;
  std::string _bits;
  std::vector<uint32_t> _hash(const std::string& input) const;
  std::vector<uint32_t> _hash2(const std::string& input) const;
  bloom_filter(int num_hash_func, std::string bits);

 public:
  bloom_filter() = delete;
  ~bloom_filter();
  //   bloom_filter(int num_hash_func, std::string bits);

  /// @brief
  /// @param fpr
  /// @param max_elements
  /// @return Returns INVALID_ARGUMENT if fpr is not in (0,1) or max_elements is
  /// not positive.
  static std::unique_ptr<bloom_filter> new_bloom_filter(double fpr,
                                                        int64_t max_elements);
  void add(const std::vector<std::string>& inputs);
  void add(const std::string& input);
  bool check(const std::string& input) const;
  std::string get_bits_string();
  int get_hash_num();
  int get_bits_num();
};

}  // namespace fucrypto
#endif