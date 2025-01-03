#include "crypto-protocol/bloomfilter.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/AES.h"
using namespace std;
using namespace oc;
namespace fucrypto {
bloom_filter::bloom_filter(int num_hash_func, std::string bits)
    : _num_hash_func(num_hash_func),
      _num_bits(bits.size() * 8),
      _bits(move(bits)) {}
bloom_filter::~bloom_filter() { cout << "~bloom_filter" << endl; };

/*
https://www.cnblogs.com/r1-12king/p/18081685
m:数组的长度
k(hash个数)　 p(错误率) 　    r(m=rn)
1 　　　　　　0.5 　　　　　   1.442695041
2 　　　　　　0.25 　　　　    2.885390082
3 　　　　　　0.125 　　　　   4.328085123
4 　　　　　　0.0625 　　　    5.770780164
5 　　　　　　0.03125 　　　   7.213475204
6 　　　　　　0.015625 　　    8.656170245
7 　　　　　　0.0078125 　　   10.09886529
8 　　　　　　0.00390625 　    11.54156033
9 　　　　　　0.001953125 　   12.98425537
10 　　　　　 0.000976563 　   14.42695041
*/

/// @brief
/// @param fpr
/// @param max_elements
/// @return Returns INVALID_ARGUMENT if fpr is not in (0,1) or max_elements is
/// not positive.
std::unique_ptr<bloom_filter> bloom_filter::new_bloom_filter(
    double fpr, int64_t max_elements) {
  //   m = -1.44 log2(e) * n
  //   k = -log2(e)
  //   cout << "num_bytes:" << endl;

  if (fpr <= 0 || fpr >= 1 || max_elements <= 0) return nullptr;
  //   cout << "num_bytes:----------" << endl;

  int num_hash_functions = static_cast<int>(std::ceil(-std::log2(fpr)));
  cout << "num_hash_functions:" << num_hash_functions << endl;

  int64_t num_bytes = static_cast<int64_t>(
      std::ceil(num_hash_functions * max_elements / std::log(2)));
  num_bytes = (num_bytes + 7) / 8;
  cout << "num_bytes:---------- " << num_bytes << endl;
  cout << ">>> r:" << (num_bytes * 8 / max_elements) << endl;
  ///////////
  //   int num_hash_functions = static_cast<int>(std::ceil(-std::log2(fpr)));
  //   int64_t num_bytes = static_cast<int64_t>(
  //       std::ceil(-max_elements * std::log2(fpr) / std::log(2) / 8));

  ///////////
  std::string bits(num_bytes, '\0');
  //   cout << "num_bytes:" << num_bytes << endl;
  //   return make_unique<bloom_filter>(num_hash_functions, std::move(bits));
  return unique_ptr<bloom_filter>(
      new bloom_filter(num_hash_functions, std::move(bits)));
}
/// @brief
/// @param input
/// @return
vector<uint32_t> bloom_filter::_hash2(const std::string &input) const {
  int num = input.size();
  if (num == 0) return vector<uint32_t>();
  int cipher_num = (num + 15) / 16;
  block cipher[cipher_num];
  cipher[cipher_num - 1] = ZeroBlock;
  memcpy(cipher, input.data(), input.size());
  mAesFixedKey.ecbEncBlocks((block *)input.data(), cipher_num, cipher);
  for (size_t i = 1; i < cipher_num; i++) {
    cipher[0] ^= cipher[i];
  }
  block blk2 = mAesFixedKey.getKey() ^ cipher[0];
  uint32_t h1 = *(uint32_t *)cipher;
  uint32_t h2 = *(uint32_t *)&blk2;
  vector<uint32_t> result(_num_hash_func);

  for (int i = 0; i < _num_hash_func; i++) {
    result[i] = (h1 + i * h2) % _num_bits;
    cout << result[i] << ",";
  }
  cout << endl;
  return result;
}
/// @brief
/// @param input
/// @return
vector<uint32_t> bloom_filter::_hash(const std::string &input) const {
  int num = input.size();
  if (num == 0) return vector<uint32_t>();
  int cipher_num = (num + 15) / 16;
  block cipher[cipher_num];
  cipher[cipher_num - 1] = ZeroBlock;
  memcpy(cipher, input.data(), input.size());
  mAesFixedKey.ecbEncBlocks((block *)input.data(), cipher_num, cipher);
  for (size_t i = 1; i < cipher_num; i++) {
    cipher[0] ^= cipher[i];
  }
  block blk2 = mAesFixedKey.getKey() ^ cipher[0];
  uint32_t h1 = *(uint32_t *)cipher;
  uint32_t h2 = *(uint32_t *)&blk2;
  vector<uint32_t> result(_num_hash_func);

  for (int i = 0; i < _num_hash_func; i++) {
    result[i] = (h1 + i * h2) % _num_bits;
    cout << result[i] << ",";
  }
  cout << endl;
  return result;
}

/// @brief
/// @param inputs
void bloom_filter::add(const std::vector<std::string> &inputs) {
  for (const std::string &input : inputs) {
    for (uint32_t index : _hash(input)) {
      _bits[index / 8] |= (1 << (index % 8));
    }
  }
}
/// @brief
/// @param input
void bloom_filter::add(const std::string &input) {
  add(std::vector<std::string>{input});
}
bool bloom_filter::check(const std::string &input) const {
  bool result = true;

  for (int32_t index : this->_hash(input)) {
    result &= ((_bits[index / 8] >> (index % 8)) & 1);
  }
  return result;
}

/// @brief
/// @return
std::string bloom_filter::get_bits_string() { return _bits; }
int bloom_filter::get_hash_num() { return _num_hash_func; }
int bloom_filter::get_bits_num() { return _num_bits; }
}  // namespace fucrypto