#include <bits/stdc++.h>
#include "crypto-protocol/bloomfilter.h"
using namespace std;
using namespace fucrypto;
class Rand {
 private:
  /* data */
 public:
  Rand(/* args */) { srand(time(NULL)); };
  int get() { return rand(); };
  ~Rand() {};
};

static void test_bloom(double fpr, int count, int count2) {
  cout << "--------- test bloomfilter -------\n";
  auto bf = bloom_filter::new_bloom_filter(fpr, count);
  int bits_num = bf->get_bits_num();
  int hash_num = bf->get_hash_num();
  printf("bits_num>: %d,hash_num>: %d\n", bits_num, hash_num);
  vector<string> inputs(count), inputs2(count2);
  for (size_t i = 0; i < count; i++) {
    inputs[i] = to_string(10000000 + i);
    // cout << "i:" << i << "," << inputs[i] << endl;
  }
  Rand rd;
  for (size_t i = 0; i < count2; i++) {
    inputs2[i] = to_string(rd.get());
  }
  bf->add(inputs);
  string bits_str = bf->get_bits_string();
  //   cout << bits_str.length() << endl;
  for (size_t i = 0; i < count; i++) {
    bool fg = bf->check(inputs[i]);
    if (!fg) {
      cout << endl << "i:" << i << ",error fg=false" << endl;
      break;
    }
    // cout << std::boolalpha << fg << ",";
    // cout << fg << ",";
  }
  cout << endl << "----------------\n";
  //
  int sum = 0;
  for (size_t i = 0; i < count2; i++) {
    bool fg = bf->check(inputs2[i]);
    if (fg) {
      cout << endl << "i:" << i << "," << fg << ",error fg=true" << endl;
      //   break;
      sum++;
      continue;
    }
    // cout << fg << ",";
  }
  cout << endl << "sum:" << sum << endl;

  /*
  n=1000
  fpr:      0.005 0.002 0.001
  num_bits: 11032 12936 14384
  num_byte: 1379  1617  1798
  hash_num: 8     9     10
   */
}

/*
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

int main(int argc, char** argv) {
  int count = 100;
  int count2 = 30;
  double fpr = 0.001;
  test_bloom(fpr, count, count2);
  return 0;
}