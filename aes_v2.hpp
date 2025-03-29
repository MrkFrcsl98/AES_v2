#include <string>
#include <type_traits>
// #include "macros.h"
// #include "typedefs.h"

#ifndef __MFAES_BLOCK_CIPHER_lbv01__
#define __MFAES_BLOCK_CIPHER_lbv01__ 0x01

#define __AES_SBOX_EL_SZ__ (0b0001 << 0b0001000)
#define __AES_RCON_SZ__ (0b0001000 << 0b0001) - 0x5
#define __AES_MCSMSZ__ (0b01 << 0b010)
#define __AES128KS__ (0b0001 << 0b0111)
#define __AES192KS__ (0b00110000 << 0b010)
#define __AES256KS__ (0b01000000 << 0b010)

// AES Substitution-box, contains 256 elements, each element is first treated as an element
// in the finite field AKA galois field GF(2^8), the inverse of each byte is
// computed in this field. After obtaining the inverse, the affine transformation
// is applied to each byte, this transformation is defined by a specific matrix and a constant
// vector. Introduces non-linearity and confusion to the algorithm, it is used by substitution
// operations such as SubBytes function.
static constexpr unsigned short int SBox[__AES_SBOX_EL_SZ__] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
    0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
    0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
    0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
    0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// AES Inverse S-box, serves the opposite purpose of SBox to reverse the substitution operation
// performed during encryption, each byte in the ciphertext needs to be transformed back
// to its original value in the plainext.
// This box also contributes to confusion, ensuring that small changes int the ciphertext
// leads to significant changes in the output.
// This box is also a 256 bytes table, where each byte is treated as an element in the finite
// field GF(2^8), after obtaining the inverse, an affine transformation is applied to
// each byte, but in reverse order compared to the SBox.
// This table, is used within the InvSubByes step during decryption, where each byte of
// the state matrix is replaced with its corresponding value from this table.
static constexpr unsigned short int InvSBox[__AES_SBOX_EL_SZ__] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
    0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
    0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
    0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
    0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
    0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
    0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
    0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
    0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// AES Round constants (RCON), this is used during key expansion to generate round keys,
// these keys are used in each round of AES encryption and decryption.
// Used in the key schedule to ensure each round key is unique, this introduces non-linearity.
// Is particularly important to ensure that no round key is reused in different rounds.
//
static constexpr unsigned short int RCon[__AES_RCON_SZ__] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// AES MixColumns matrix, this is used during encryption process to provide
// diffusion to the cipher, this table treats each column of the state as a
// polynomial over the finite field GF(2^8), the transformation is defined
// by multiplying each column of the state matrix by a fixed
// polynomial matrix. This table is important to provide security by generating diffusion.
static constexpr unsigned short int MixCols[__AES_MCSMSZ__][__AES_MCSMSZ__] = {
    {0x02, 0x03, 0x01, 0x01}, {0x01, 0x02, 0x03, 0x01}, {0x01, 0x01, 0x02, 0x03}, {0x03, 0x01, 0x01, 0x02}};

// AES Inverse MixColumns matrix, this is used during decryption to inverse the MixColums
// operation, just like MixColumns table, this table operates on the state matrix,
// which is a 4*4 array of bytes. This table is primary used for reversing diffusion
// effect introduced by MixColumns operation during encryption, this allows to recover
// the original plaintext from the ciphertext.
static constexpr unsigned short int InvMixCols[__AES_MCSMSZ__][__AES_MCSMSZ__] = {
    {0x0E, 0x0B, 0x0D, 0x09}, {0x09, 0x0E, 0x0B, 0x0D}, {0x0D, 0x09, 0x0E, 0x0B}, {0x0B, 0x0D, 0x09, 0x0E}};

// Nb referse to the number of columns(32-bit words) in the state array, plays a crucial
// role in AES by defining the structure of the state matrix.
// For AES, the value of this constant is always 4, regardless of the key size.
//
static constexpr unsigned short int Nb = (0b0001 << 0b0010);

static constexpr unsigned short int AES128_BLOCK_CIPHER = (0b0001 << 0b0111);

#endif

typedef unsigned char __uint8T;
typedef unsigned short int __uint16T;
typedef unsigned int __uint32T;
typedef unsigned long int __uint64T;
typedef unsigned long long int __uint128T;
typedef const char *__ccptrT;
typedef bool __bitT;

template <typename T> struct Sequence {
  __uint64T size{0};
  T *data{nullptr};

  inline Sequence() noexcept {};

  inline Sequence(__uint64T s) noexcept { this->size = s; };

  inline Sequence(const Sequence<T> &o) noexcept { *this = o; };

  inline Sequence(Sequence<T> &&o) noexcept { *this = std::move(o); };

  const Sequence<T> &operator=(const Sequence<T> &o) noexcept {
    if (o.data == nullptr || o.size == 0) [[unlikely]]
      return *this;
    if (this->data == nullptr) [[likely]] {
      this->data = (T *)malloc(o.size * sizeof(T));
    }
    while (this->size < o.size) {
      data[this->size] = o.data[this->size];
      ++this->size;
    }
    return *this;
  };

  const Sequence<T> &operator=(Sequence<T> &&o) noexcept {
    if (o.data == nullptr || o.size == 0) [[unlikely]]
      return *this;
    if (this->data == nullptr) [[likely]] {
      this->data = (T *)malloc(o.size * sizeof(T));
    }

    while (this->size < o.size) {
      this->data[this->size] = o[this->size];
      o.data[this->size] = '\0';
      ++this->size;
    }
    free(o.data);
    o.data = nullptr;
    o.size = 0;
    return *this;
  };

  __attribute__((warn_unused_result, always_inline, pure)) const T operator[](const __uint64T i) const noexcept {
    if (i < size)
      return data[i];
    else
      return T{};
  };

  __attribute__((warn_unused_result, always_inline, pure)) T &operator[](const __uint64T i) noexcept {
    return data[i < size ? i : i % size];
  };

  __attribute__((warn_unused_result, always_inline, pure)) const bool operator==(const Sequence<T> &o) const noexcept {
    if (this->size != o.size)
      return false;
    if (o.size > 0) [[likely]] {
      __uint64T c{0};
      do {
        if (this->data[c] != o.data[c])
          return false;
      } while (c++ < o.size && c < this->size);
    }
    return true;
  };

  __attribute__((warn_unused_result, always_inline, pure)) const bool operator>(const Sequence<T> &o) const noexcept {
    return this->size > o.size;
  };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator>=(const Sequence<T> &o) const noexcept {
    return this->size > o.size;
  };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator<(const Sequence<T> &o) const noexcept {
    return this->size > o.size;
  };
  __attribute__((warn_unused_result, always_inline, pure)) const bool operator<=(const Sequence<T> &o) const noexcept {
    return this->size > o.size;
  };

  __attribute__((always_inline)) inline void reverse_sequence() noexcept {
    T *tmp_seq = (T *)malloc(this->size * sizeof(T));
    __uint64T s = 0;
    while (s < size) {
      tmp_seq[s] = data[s];
      ++s;
    }
    __uint64T tc{0};
    do {
      data[tc] = tmp_seq[(size - 1) - tc];
    } while (++tc < size);
    free(tmp_seq);
  };

  __attribute__((always_inline)) inline void realloc_byte(const __uint64T i, const T n) noexcept {
    if (i >= size)
      return;
    data[i] = n;
  };

  inline ~Sequence() noexcept {
    if (this->data != nullptr) {
      free(this->data);
    }
    size = 0;
  }
};

class Converter {
public:
  Converter() = delete;
  ~Converter() = default;
  static __ccptrT asciiToBinary(__ccptrT input) noexcept {
    static __ccptrT const lookup[256] = {
        "00000000", "00000001", "00000010", "00000011", "00000100", "00000101", "00000110", "00000111", "00001000", "00001001", "00001010",
        "00001011", "00001100", "00001101", "00001110", "00001111", "00010000", "00010001", "00010010", "00010011", "00010100", "00010101",
        "00010110", "00010111", "00011000", "00011001", "00011010", "00011011", "00011100", "00011101", "00011110", "00011111", "00100000",
        "00100001", "00100010", "00100011", "00100100", "00100101", "00100110", "00100111", "00101000", "00101001", "00101010", "00101011",
        "00101100", "00101101", "00101110", "00101111", "00110000", "00110001", "00110010", "00110011", "00110100", "00110101", "00110110",
        "00110111", "00111000", "00111001", "00111010", "00111011", "00111100", "00111101", "00111110", "00111111", "01000000", "01000001",
        "01000010", "01000011", "01000100", "01000101", "01000110", "01000111", "01001000", "01001001", "01001010", "01001011", "01001100",
        "01001101", "01001110", "01001111", "01010000", "01010001", "01010010", "01010011", "01010100", "01010101", "01010110", "01010111",
        "01011000", "01011001", "01011010", "01011011", "01011100", "01011101", "01011110", "01011111", "01100000", "01100001", "01100010",
        "01100011", "01100100", "01100101", "01100110", "01100111", "01101000", "01101001", "01101010", "01101011", "01101100", "01101101",
        "01101110", "01101111", "01110000", "01110001", "01110010", "01110011", "01110100", "01110101", "01110110", "01110111", "01111000",
        "01111001", "01111010", "01111011", "01111100", "01111101", "01111110", "01111111", "10000000", "10000001", "10000010", "10000011",
        "10000100", "10000101", "10000110", "10000111", "10001000", "10001001", "10001010", "10001011", "10001100", "10001101", "10001110",
        "10001111", "10010000", "10010001", "10010010", "10010011", "10010100", "10010101", "10010110", "10010111", "10011000", "10011001",
        "10011010", "10011011", "10011100", "10011101", "10011110", "10011111", "10100000", "10100001", "10100010", "10100011", "10100100",
        "10100101", "10100110", "10100111", "10101000", "10101001", "10101010", "10101011", "10101100", "10101101", "10101110", "10101111",
        "10110000", "10110001", "10110010", "10110011", "10110100", "10110101", "10110110", "10110111", "10111000", "10111001", "10111010",
        "10111011", "10111100", "10111101", "10111110", "10111111", "11000000", "11000001", "11000010", "11000011", "11000100", "11000101",
        "11000110", "11000111", "11001000", "11001001", "11001010", "11001011", "11001100", "11001101", "11001110", "11001111", "11010000",
        "11010001", "11010010", "11010011", "11010100", "11010101", "11010110", "11010111", "11011000", "11011001", "11011010", "11011011",
        "11011100", "11011101", "11011110", "11011111", "11100000", "11100001", "11100010", "11100011", "11100100", "11100101", "11100110",
        "11100111", "11101000", "11101001", "11101010", "11101011", "11101100", "11101101", "11101110", "11101111", "11110000", "11110001",
        "11110010", "11110011", "11110100", "11110101", "11110110", "11110111", "11111000", "11111001", "11111010", "11111011", "11111100",
        "11111101", "11111110", "11111111"};

    static char result[8192];
    size_t inputLength = 0;
    while (input[inputLength] != '\0') {
      ++inputLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < inputLength; ++i) {
      __ccptrT binary = lookup[static_cast<unsigned char>(input[i])];
      for (int j = 0; j < 8; ++j) {
        result[resultIndex++] = binary[j];
      }
    }
    result[resultIndex] = '\0';
    return result;
  }

  static __ccptrT asciiToHex(__ccptrT input) noexcept {
    static const char hexDigits[17] = "0123456789ABCDEF";
    static char result[4096];
    size_t inputLength = 0;
    while (input[inputLength] != '\0') {
      ++inputLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < inputLength; ++i) {
      result[resultIndex++] = hexDigits[static_cast<unsigned char>(input[i]) >> 4];
      result[resultIndex++] = hexDigits[static_cast<unsigned char>(input[i]) & 0x0F];
    }
    result[resultIndex] = '\0';
    return result;
  }

  static __ccptrT binaryToAscii(__ccptrT binary) noexcept {
    static char result[1024];
    size_t binaryLength = 0;
    while (binary[binaryLength] != '\0') {
      ++binaryLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < binaryLength; i += 8) {
      char byteString[9] = {0};
      for (int j = 0; j < 8; ++j) {
        byteString[j] = binary[i + j];
      }
      char asciiChar = static_cast<char>(strtol(byteString, nullptr, 2));
      result[resultIndex++] = asciiChar;
    }
    result[resultIndex] = '\0';
    return result;
  }

  static __ccptrT hexToAscii(__ccptrT hex) noexcept {
    static char result[2048];
    size_t hexLength = 0;
    while (hex[hexLength] != '\0') {
      ++hexLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < hexLength; i += 2) {
      char byteString[3] = {0};
      byteString[0] = hex[i];
      byteString[1] = hex[i + 1];
      char asciiChar = static_cast<char>(strtol(byteString, nullptr, 16));
      result[resultIndex++] = asciiChar;
    }
    result[resultIndex] = '\0';
    return result;
  }

  static __ccptrT binaryToHex(__ccptrT binary) noexcept {
    static const char hexDigits[] = "0123456789ABCDEF";
    static char result[1024];
    size_t binaryLength = 0;
    while (binary[binaryLength] != '\0') {
      ++binaryLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < binaryLength; i += 4) {
      char nibbleString[5] = {0};
      for (int j = 0; j < 4; ++j) {
        nibbleString[j] = binary[i + j];
      }
      int hexValue = strtol(nibbleString, nullptr, 2);
      result[resultIndex++] = hexDigits[hexValue];
    }
    result[resultIndex] = '\0';
    return result;
  }

  static __ccptrT hexToBinary(__ccptrT hex) noexcept {
    static char result[8192];
    size_t hexLength = 0;
    while (hex[hexLength] != '\0') {
      ++hexLength;
    }
    size_t resultIndex = 0;
    for (size_t i = 0; i < hexLength; ++i) {
      int hexValue = (hex[i] >= '0' && hex[i] <= '9') ? hex[i] - '0' : (hex[i] - 'A' + 10);
      for (int j = 3; j >= 0; --j) {
        result[resultIndex++] = (hexValue & (1 << j)) ? '1' : '0';
      }
    }
    result[resultIndex] = '\0';
    return result;
  }
};

#ifdef __MFAES_BLOCK_CIPHER_lbv01__
#ifdef __AES_SBOX_EL_SZ__
#ifdef __AES_RCON_SZ__
#ifdef __AES_MCSMSZ__

namespace AESCrypto {

class InhInitOpClass {
public:
  InhInitOpClass() = default;
  ~InhInitOpClass() = default;
  __attribute__((cold, pure, warn_unused_result, nonnull)) inline const __uint64T _getSequenceSize(__ccptrT input) noexcept {
    if (input == nullptr || *input == '\0') [[unlikely]]
      return 0;
    __uint64T size{0};
    __uint16T c = (*input);
    do {
      ++size;
    } while ((c = *(++input)) != '\0');
    return size;
  };

  template <typename T>
  __attribute__((nonnull, warn_unused_result, pure)) inline const Sequence<T> _genBlockSequence(__ccptrT seq, const __uint64T n) noexcept {
    struct Sequence<T> sequence;
    sequence.data = (T *)malloc(n * sizeof(T));
    sequence.size = 0;
    __uint16T c = (*seq);
    do {
      sequence.data[sequence.size++] = (T)c;
    } while ((c = *(++seq)) != '\0' && sequence.size < n);
    return sequence;
  };

protected:
  __uint64T _iSz;
  __uint64T _kSz;
  struct Sequence<__uint16T> _input_bits;
  struct Sequence<__uint16T> _key_bits;
};

template <__uint16T BlockSz> struct IsValidBlockSize {
  static const bool value = (BlockSz == __AES128KS__ || BlockSz == __AES192KS__ || BlockSz == __AES256KS__);
};

template <__uint16T BlockSz, typename Enable = void> class Aes;

template <__uint16T BlockSz> class Aes<BlockSz, typename std::enable_if<IsValidBlockSize<BlockSz>::value>::type> : public InhInitOpClass {
public:
  inline explicit Aes() noexcept = delete;
  inline Aes(const Aes &_c) noexcept = delete;
  inline Aes(const Aes &&_c) noexcept = delete;
  inline Aes(__ccptrT input, __ccptrT key) {
    if (!this->_paramStateAssert(input, key)) {
      throw std::invalid_argument("invalid input or key!");
    }
    this->_dataInitialization(input, key);
  };

  inline ~Aes() noexcept = default;

private:
  __attribute__((cold, warn_unused_result)) inline const bool _paramStateAssert(__ccptrT input, __ccptrT key) noexcept {
    if ((this->_iSz = this->_getSequenceSize(input)) >= __UINT64_MAX__ || this->_iSz == 0) [[unlikely]] {
      return false;
    }
    if ((this->_kSz = this->_getSequenceSize(key)) >= __UINT16_MAX__ || this->_kSz == 0) [[unlikely]] {
      return false;
    }
    return true;
  };

  __attribute__((cold, nonnull)) inline void _dataInitialization(__ccptrT input, __ccptrT key) noexcept {

    this->_input_bits = this->_genBlockSequence<__uint16T>(input, this->_iSz);
    this->_key_bits = this->_genBlockSequence<__uint16T>(key, this->_kSz);
  };
};
}; // namespace AESCrypto

#endif
#endif
#endif
#endif
