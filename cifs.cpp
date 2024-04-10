/*
MIT License

Copyright (c) 2024 Denis Korenev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <random>
#include <vector>
#include <ctime>
#include <chrono>
#include <iostream>
#include <cassert>
#include <cstring>
#include <fstream>

#include <stdio.h>
#include <math.h>

#define ADD_EXPORTS
#define IMECLUI_IMPLEMENTATION
#include "src/imeclui.h"

#define ARGPARSE_IMPLEMENTATION
#include "src/argparse.h"

#include "src/tqdm.hpp"

// ===--- CONFIG ---============================================================
#define __CONFIG

// Is tests to compile
#define TESTS_ENABLED

// Is tests & benchmarks verbose
#define TESTS_VERBOSE

// ===--- MACROS ---============================================================
#define __MACROS

int log_verbose_lvl = 0; // Extended logs
int log_common_lvl = 1;  // Common logs
int log_quiet_lvl = 0;   // Errors only
int log_shutup_lvl = 0;  // No logs

int shuffle = 0; // Use byte shuffling, default: 0

// Time measurement
#define GET_CURR_TIME std::chrono::system_clock::now()
#define GET_TIME_DIFF(start, end) \
    std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()

// Common integer type (unsigned)
#define uint_t unsigned long long int
// Common integer type (signed)
#define int_t long long int

// Common byte type
#define byte_t uint8_t

// Copies vector's data to array
#define SCRAP_VECTOR(dst, vec, T) \
    dst = ALLOC(T, (vec).size()); \
    memcpy(dst, (vec).data(), (vec).size() * sizeof(T))

// Colors
#define C_RESET \
    IME_ESC     \
    IME_RESET   \
    IME_ESC_END
#define C_RED \
    IME_ESC   \
    IME_RED   \
    IME_ESC_END
#define C_GREEN \
    IME_ESC     \
    IME_GREEN   \
    IME_ESC_END
#define C_CYAN                 \
    IME_ESC                    \
    IME_RGB_COLOR(0, 200, 180) \
    IME_ESC_END
#define C_DIMM       \
    IME_ESC          \
    IME_BRIGHT_BLACK \
    IME_ESC_END

#define C_HEADER                \
    IME_ESC                     \
    IME_RGB_COLOR(255, 117, 24) \
    IME_ESC_END

#define C_ERROR \
    C_RED

// Strings
#define TESTS_STR                \
    IME_ESC                      \
    IME_RGB_COLOR(255, 255, 100) \
    IME_ESC_END                  \
    "TESTS:" C_RESET "\n"
#define INPUT_STR \
    "\n" C_DIMM   \
    "Input:" C_RESET " "
#define INVALID_INPUT_STR \
    C_RED                 \
    "Invalid input" C_RESET "\n"

#define RSA_STR                  \
    IME_ESC                      \
    IME_RGB_COLOR(100, 100, 255) \
    IME_ESC_END                  \
    "RSA:" C_RESET "\n"
#define ELGAMAL_STR              \
    IME_ESC                      \
    IME_RGB_COLOR(100, 255, 100) \
    IME_ESC_END                  \
    "ElGamal:" C_RESET "\n"
#define ELGSIG_STR            \
    IME_ESC                   \
    IME_RGB_COLOR(255, 85, 0) \
    IME_ESC_END               \
    "ElGamal Signature:" C_RESET "\n"
#define DES_STR                 \
    IME_ESC                     \
    IME_RGB_COLOR(64, 130, 109) \
    IME_ESC_END                 \
    "DES:" C_RESET "\n"

#ifdef TESTS_VERBOSE
#define PASSED_STR \
    IME_ESC        \
    IME_GREEN      \
    IME_ESC_END    \
    "===--> PASSED\n\n" C_RESET
#define PASSED_TIME_FMT \
    IME_ESC             \
    IME_GREEN           \
    IME_ESC_END         \
    "===--> PASSED: %.6fms\n\n" C_RESET
#define FAILED_STR \
    IME_ESC        \
    IME_RED        \
    IME_ESC_END    \
    "===--> FAILED\n\n" C_RESET
#else
#define PASSED_STR \
    IME_ESC        \
    IME_GREEN      \
    IME_ESC_END    \
    "PASSED\n" C_RESET
#define PASSED_TIME_FMT \
    IME_ESC             \
    IME_GREEN           \
    IME_ESC_END         \
    "PASSED: %.6fms\n" C_RESET
#define FAILED_STR \
    IME_ESC        \
    IME_RED        \
    IME_ESC_END    \
    "FAILED\n" C_RESET
#endif // TESTS_VERBOSE

#ifdef _WIN32
std::ofstream devnull("NUL");
#else
std::ofstream devnull("/dev/null");
#endif

// Main assert, in a 'slay💅' style
#define MASSERT(cond, msg)                           \
    if (!(cond))                                     \
    {                                                \
        printf(C_ERROR);                             \
        printf("[ASSERTION FAILED] <%s:%s:%d> %s\n", \
               __FILE__, __func__, __LINE__, msg);   \
        printf(C_RESET " ");                         \
        exit(1);                                     \
    }

// Preferrable allocators
#define ALLOC(T, size) ((T *)malloc((size) * sizeof(T)))
#define CALLOC(T, size) ((T *)calloc((size), sizeof(T)))
#define REALLOC(T, ptr, size) ((T *)realloc(ptr, (size) * sizeof(T)))
#define FREE(ptr)    \
    if (ptr != NULL) \
    {                \
        free(ptr);   \
        ptr = NULL;  \
    }

// ===--- ESSENTIALS ---========================================================
#define __ESSENTIALS

/// @brief Check if the number is prime
/// @param x number
/// @return true if the number is prime, false otherwise
bool is_prime(uint_t x)
{
    if (x < 2)
    {
        return false;
    }
    for (uint_t i = 2; i * i <= x; i++)
    {
        if (x % i == 0)
        {
            return false;
        }
    }
    return true;
}

/// @brief Exponentiation
/// @tparam T type of the base
/// @param x base
/// @param p power
/// @return x^p
template <typename T>
T pow(T x, uint_t p)
{
    T res = 1;
    for (uint_t i = 0; i < p; i++)
    {
        res *= x;
    }
    return res;
}

/// @brief Fast modular exponentiation
/// @tparam T type of the base
/// @param x base
/// @param pow power
/// @param mod modulo
/// @return x^pow % mod
template <typename T>
T pow_mod(T x, uint_t pow, uint_t mod)
{
    T res = 1;
    for (uint_t i = 0; i < pow; i++)
    {
        res = (res * x) % mod;
    }
    return res;
}

/// @brief Check if the number is a primitive root modulo p
/// @param g number
/// @param p modulo
/// @return true if g is a primitive root modulo p, false otherwise
bool is_primitive_root_mod(uint_t g, uint_t p)
{
    for (uint_t j = 1; j < p - 1; j++)
    {
        if (pow_mod(g, j, p) == 1)
        {
            return false;
        }
    }
    return true;
}

/// @brief Get the primitive root modulo p
/// @param p modulo
/// @return primitive root modulo p
uint_t primitive_root_mod(uint_t p)
{
    for (uint_t i = 2; i < p; i++)
    {
        if (is_primitive_root_mod(i, p))
        {
            return i;
        }
    }
    return -1;
}

/// @brief Coprime number to the given one
/// @param num number
/// @return coprime number
uint_t coprime(uint_t num)
{
    for (uint_t i = 2; i < num; i++)
    {
        if (num % i != 0)
        {
            return i;
        }
    }
    return -1;
}

/// @brief Get the multiplicative inverse of a number
/// @param k number
/// @param p modulo
/// @return multiplicative inverse of k modulo p
uint_t multiplicative_inverse(uint_t k, uint_t p)
{
    for (uint_t i = 1; i < p; i++)
    {
        if ((k * i) % p == 1)
        {
            return i;
        }
    }
    return -1;
}

/// @brief Get the lesser of two numbers
/// @tparam T type of the numbers
/// @param a
/// @param b
/// @return
template <typename T>
T min(T a, T b)
{
    return a < b ? a : b;
}

/// @brief Check if two strings are equal
/// @param str1
/// @param str2
/// @return true if strings are equal, false otherwise
bool is_str_eq(const char *str1, const char *str2)
{
    return strcmp(str1, str2) == 0;
}

/// @brief Shuffle data for encryption
/// @param data
/// @param data_size
void byte_shuffle(byte_t *data, size_t data_size)
{
    // b = (b+a) % 0xFF
    byte_t b = 0x00;
    for (size_t i = 0; i < data_size; i++)
    {
        b = (b + data[i]) % 0xFF;
        data[i] = b;
    }
}

/// @brief Shuffle data for encryption
/// @tparam T type of the data
/// @param data
/// @param data_size
template <typename T>
void type_shuffle(T *data, size_t data_size)
{
    T mask = 0;
    for (size_t i = 0; i < sizeof(T); i++)
    {
        mask = (mask << 8) + 0xFF;
    }
    // b = (b+a) % 0xFF
    T b = 0x00;
    for (size_t i = 0; i < data_size; i++)
    {
        b = (b + data[i]) % mask;
        data[i] = b;
    }
}

/// @brief Unshuffle data after decryption
/// @param data
/// @param data_size
void byte_unshuffle(byte_t *data, size_t data_size)
{
    byte_t b = 0x00;
    for (size_t i = 0; i < data_size; i++)
    {
        byte_t current = data[i];
        data[i] = (data[i] - b + 0xFF) % 0xFF;
        b = current;
    }
}

/// @brief Unshuffle data after decryption
/// @tparam T type of the data
/// @param data
/// @param data_size
template <typename T>
void type_unshuffle(T *data, size_t data_size)
{
    T mask = 0;
    for (size_t i = 0; i < sizeof(T); i++)
    {
        mask = (mask << 8) + 0xFF;
    }
    T b = 0x00;
    for (size_t i = 0; i < data_size; i++)
    {
        T current = data[i];
        data[i] = (data[i] - b + mask) % mask;
        b = current;
    }
    // NOTE [Kseen]: this is not a perfect unshuffle, but it's good enough
    // for some reasons it may return values a 1 lower
    // for (size_t i = 0; i < data_size; i++)
    //     data[i]++;
}

// ===--- SERVICE ---===========================================================
#define __SERVICE

/// @brief Length of the number in hexadecimal representation
/// @param num number
/// @return length of the number in hexadecimal representation
uint_t hex_num_len(uint_t num)
{
    uint_t res = 1;
    while (num > 15)
    {
        num >>= 4;
        res++;
    }
    return res;
}

/// @brief Length of the number in decimal representation
/// @param num number
/// @return length of the number in decimal representation
uint_t dec_num_len(uint_t num)
{
    uint_t res = 1;
    while (num > 9)
    {
        num /= 10;
        res++;
    }
    return res;
}

/// @brief Write array of integers to a file as decimal numbers with
/// leading zeros
/// @param data array of integers
/// @param data_size
/// @param N modulo
/// @param file_name file name
/// @warning DEPRECATED, will be removed in future
void fwrite_dec_modulo(uint_t *data, size_t data_size,
                       uint_t N, const char *file_name)
{
    size_t num_len = dec_num_len(N);
    FILE *file = fopen(file_name, "w");
    MASSERT(file != NULL, "Can't open file for writing");
    for (size_t i = 0; i < data_size; i++)
    {
        for (size_t j = 0; j < num_len - dec_num_len(data[i]); j++)
        {
            fprintf(file, "0");
        }
        fprintf(file, "%lld", (int64_t)data[i]);
    }
    fclose(file);
}

/// @brief Write array of integers to a file as hexadecimal numbers with
/// leading zeros
/// @param data array of integers
/// @param data_size
/// @param N modulo
/// @param file_name file name
/// @warning DEPRECATED, will be removed in future
void fwrite_hex_modulo(uint_t *data, size_t data_size, uint_t N,
                       const char *file_name)
{
    size_t num_len = hex_num_len(N);
    FILE *file = fopen(file_name, "w");
    MASSERT(file != NULL, "Can't open file for writing");
    for (size_t i = 0; i < data_size; i++)
    {
        fprintf(file, "%0*llX", (int)num_len, (uint64_t)data[i]);
    }
    fclose(file);
}

/// @brief Write byte array to a binary file
/// @param bytes
/// @param size
/// @param file_name
void fwrite_bin(const byte_t *bytes, size_t size, const char *file_name)
{
    FILE *file = fopen(file_name, "wb");
    MASSERT(file != NULL, "Can't open file for writing");
    fwrite(bytes, 1, size, file);
    fclose(file);
}

/// @brief Write array of integers to a sting buffer as decimal numbers with
/// leading zeros
/// @param data array of integers
/// @param data_size
/// @param N modulo
/// @param str pointer to the result
/// @warning The result must be freed after usage
void swrite_dec_modulo(uint_t *data, size_t data_size,
                       uint_t N, char **str)
{
    size_t num_len = dec_num_len(N);
    char *res = ALLOC(char, (data_size * num_len));
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        for (size_t j = 0; j < num_len - dec_num_len(data[i]); j++)
        {
            *res = '0';
            res++;
        }
        sprintf(res, "%lld", (int64_t)data[i]);
        res += dec_num_len(data[i]);
    }
    res -= data_size * num_len;
    *str = res;
}

/// @brief Write array of integers to a sting buffer as decimal numbers with
/// leading zeros
/// @param data array of integers
/// @param data_size
/// @param str pointer to the result
/// @warning The result must be freed after usage
void swrite_dec(uint_t *data, size_t data_size, char **str)
{
    // TODO: remove
    size_t max_len = 20;
    char *res = CALLOC(char, data_size * 20);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        size_t num_len = dec_num_len(data[i]);
        for (size_t j = 0; j < max_len - num_len; j++)
        {
            *res = '0';
            res++;
        }
        sprintf(res, "%lld", (int64_t)data[i]);
        res += num_len;
    }
    res -= data_size * max_len;
    *str = res;
}

/// @brief Write array of integers to a sting buffer as hexadecimal numbers with
/// leading zeros
/// @param data array of integers
/// @param data_size
/// @param N modulo
/// @param str pointer to the result
/// @warning The result must be freed after usage
void swrite_hex_modulo(uint_t *data, size_t data_size, uint_t N, char **str)
{
    size_t num_len = hex_num_len(N);
    char *res = ALLOC(char, data_size *num_len);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        sprintf(res, "%0*llx", (int)num_len, (uint64_t)data[i]);
        res += num_len;
    }
    res -= data_size * num_len;
    *str = res;
}

/// @brief Write byte array to a string buffer as hexadecimal numbers with
/// leading zeros
/// @param data
/// @param data_size
/// @param str pointer to the result
/// @warning The result must be freed after usage
void swrite_hex(byte_t *data, size_t data_size, char **str)
{
    char *res = ALLOC(char, data_size * 2 + 1);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        sprintf(res, "%02X", data[i]);
        res += 2;
    }
    res -= data_size * 2;
    *res = '\0';
    *str = res;
}

/// @brief Read array of integers from a file as decimal numbers with
/// leading zeros
/// @param data pointer to the result
/// @param data_size pointer to the result
/// @param N modulo
/// @param file_name file name
/// @warning The result must be freed after usage
void fread_dec_modulo(uint_t **data, size_t *data_size, uint_t N,
                      const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    MASSERT(file != NULL, "Can't open file for reading");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = ALLOC(char, file_size);
    MASSERT(buffer != NULL, "Memory allocation failed");
    fread(buffer, 1, file_size, file);
    fclose(file);
    size_t num_len = dec_num_len(N);
    size_t num_count = file_size / num_len;
    uint_t *res = ALLOC(uint_t, num_count);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < num_count; i++)
    {
        uint_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = num * 10 + buffer[i * num_len + j] - '0';
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
    FREE(buffer);
}

/// @brief Read array of integers from a file as hexadecimal numbers with
/// leading zeros
/// @param data pointer to the result
/// @param data_size pointer to the result
/// @param N modulo
/// @param file_name
/// @warning The result must be freed after usage
void fread_hex_modulo(uint_t **data, size_t *data_size, uint_t N,
                      const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    MASSERT(file != NULL, "Can't open file for reading");

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = ALLOC(char, file_size);
    MASSERT(buffer != NULL, "Memory allocation failed");

    fread(buffer, 1, file_size, file);
    fclose(file);
    size_t num_len = hex_num_len(N);
    size_t num_count = file_size / num_len;

    uint_t *res = ALLOC(uint_t, num_count);
    MASSERT(res != NULL, "Memory allocation failed");

    for (size_t i = 0; i < num_count; i++)
    {
        uint_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = (num << 4) + buffer[i * num_len + j] - '0' -
                  ((uint_t)((buffer[i * num_len + j] >= 'A') &&
                            (buffer[i * num_len + j] <= 'F')) *
                   7) -
                  ((uint_t)((buffer[i * num_len + j] >= 'a') &&
                            (buffer[i * num_len + j] <= 'f')) *
                   39);
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
    FREE(buffer);
}

/// @brief Read binary file to a byte array
/// @param bytes pointer to the result
/// @param size pointer to the result
/// @param file_name
/// @warning The result must be freed after usage
void fread_bin(byte_t **bytes, size_t *size, const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file for reading");
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *bytes = ALLOC(byte_t, *size);
    MASSERT(*bytes != NULL, "Memory allocation failed");
    fread(*bytes, 1, *size, file);
    fclose(file);
}

/// @brief Read array of integers from a string buffer as decimal numbers with
/// leading zeros
/// @param str string buffer
/// @param data pointer to the result
/// @param data_size
/// @param N
/// @warning The result must be freed after usage
void sread_dec_modulo(char *str, uint_t **data, size_t *data_size, uint_t N)
{
    // chop str to N-sized parts, then atoi them
    size_t num_len = dec_num_len(N);
    size_t num_count = strlen(str) / num_len;
    uint_t *res = ALLOC(uint_t, num_count);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < num_count; i++)
    {
        uint_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = num * 10 + str[i * num_len + j] - '0';
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
}

/// @brief Read array of integers from a string buffer as hexadecimal numbers with
/// leading zeros
/// @param str string buffer
/// @param data pointer to the result
/// @param data_size
/// @param N
/// @warning The result must be freed after usage
void sread_hex_modulo(char *str, uint_t **data, size_t *data_size, uint_t N)
{
    size_t num_len = hex_num_len(N);
    size_t num_count = strlen(str) / num_len;
    uint_t *res = ALLOC(uint_t, num_count);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < num_count; i++)
    {
        uint_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = (num << 4) + str[i * num_len + j] - '0' -
                  ((uint_t)((str[i * num_len + j] >= 'A') &&
                            (str[i * num_len + j] <= 'F')) *
                   7) -
                  ((uint_t)((str[i * num_len + j] >= 'a') &&
                            (str[i * num_len + j] <= 'f')) *
                   39);
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
}

/// @brief Print array of integers as decimal numbers
/// @tparam T type of the array elements
/// @param data
/// @param data_size
template <typename T>
void print_array(T *data, size_t data_size)
{
    printf("(%lld){", data_size);
    for (size_t i = 0; i < data_size - 1; i++)
    {
        printf("%llu, ", (unsigned long long)data[i]);
    }
    printf("%llu}\n", (unsigned long long)data[data_size - 1]);
}

/// @brief Print array of data with given format string
/// @tparam T
/// @param data
/// @param size
/// @param fmt
template <typename T>
void print_array_fmt(T *data, size_t size, char *fmt)
{
    printf("(%lld){", size);
    for (size_t i = 0; i < size - 1; i++)
    {
        printf(fmt, data[i]);
        printf(", ");
    }
    printf(fmt, data[size - 1]);
    printf("}\n");
}

/// @brief Print array of integers as ASCII characters
/// @param data
/// @param data_size
void print_array_ascii(char *data, size_t data_size)
{
    for (size_t i = 0; i < data_size; i++)
    {
        printf("%c", data[i]);
    }
    printf("\n");
}

/// @brief Print array of integers as hexadecimal numbers
/// @tparam T type of the array elements
/// @param data
/// @param data_size
template <typename T>
void print_array_hex(T *data, size_t data_size)
{
    printf("(%lld){", data_size);
    for (size_t i = 0; i < data_size - 1; i++)
    {
        printf("0x%0*llX, ", (int)sizeof(T) * 2, (unsigned long long)data[i]);
    }
    printf("0x%0*llX}\n", (int)sizeof(T) * 2,
           (unsigned long long)data[data_size - 1]);
}

/// @brief Print array of integers as hexadecimal numbers in one line
/// @tparam T type of the array elements
/// @param data
/// @param data_size
template <typename T>
void print_array_hex_line(T *data, size_t data_size)
{
    for (size_t i = 0; i < data_size; i++)
    {
        printf("%0*llx", (int)sizeof(T) * 2, (unsigned long long)data[i]);
    }
}

/// @brief Print byte as binary number
/// @param byte
void print_byte_bin(byte_t byte)
{
    int i;
    for (i = 0; i < 8; i++)
    {
        byte_t shift_byte = 0x01 << (7 - i);
        if (shift_byte & byte)
        {
            printf("1");
        }
        else
        {
            printf("0");
        }
    }
}

/// @brief Compare two arrays
/// @tparam T type of the array elements
/// @param arr1 first array
/// @param arr1_size
/// @param arr2 second array
/// @param arr2_size
/// @return true if arrays are equal, false otherwise
template <typename T>
bool cmp_arrays(T *arr1, size_t arr1_size, T *arr2, size_t arr2_size)
{
    if (arr1_size != arr2_size)
    {
        return false;
    }
    for (size_t i = 0; i < arr1_size; i++)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }
    return true;
}

/// @brief Convert array of integers to a null-terminated
/// string of ASCII characters
/// @param data array of integers
/// @param data_size
/// @param str pointer to the result
/// @warning The result must be freed after usage
void convert_array_to_str(uint_t *data, size_t data_size, char **str)
{
    char *res = CALLOC(char, data_size);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = (char)data[i];
    }
    *str = res;
}

/// @brief Convert null-terminated string of ASCII characters to an
/// array of integers
/// @param str null-terminated string of ASCII characters
/// @param data pointer to the result
/// @param data_size
/// @warning The result must be freed after usage
void convert_str_to_array(char *str, uint_t **data, size_t *data_size)
{
    size_t str_len = strlen(str);
    uint_t *res = ALLOC(uint_t, str_len);
    MASSERT(res != NULL, "Memory allocation failed");
    for (size_t i = 0; i < str_len; i++)
    {
        res[i] = (uint_t)str[i];
    }
    *data = res;
    *data_size = str_len;
}

/// @brief Parse string of integers to an array of integers
/// @param str string of integers
/// @param data pointer to the result
/// @param data_size
/// @warning The result must be freed after usage
void parse_str_to_ints(char *str, uint_t **data, size_t *data_size)
{
    for (size_t i = 0; i < strlen(str); i++)
    {
        if (str[i] == ',' ||
            str[i] == ';' ||
            str[i] == '\n' ||
            str[i] == '\t' ||
            str[i] == '\r')
        {
            str[i] = ' ';
        }
    }
    std::vector<uint_t> lst;
    char *token = strtok(str, " ");
    while (token != NULL)
    {
        lst.push_back(atoi(token));
        token = strtok(NULL, " ");
    }
    *data_size = lst.size();
    SCRAP_VECTOR(*data, lst, uint_t);
    MASSERT(*data != NULL, "Memory allocation failed");
}

/// @brief Check if the array contains only ASCII characters
/// @param data
/// @param data_size
/// @return true if the string contains only ASCII characters, false otherwise
bool is_array_ascii(uint_t *data, size_t data_size)
{
    for (size_t i = 0; i < data_size; i++)
    {
        if (data[i] > 255)
        {
            return false;
        }
    }
    return true;
}

/// @brief Check if the string contains any of ASCII characters
/// @param str
/// @return true if the string contains any of ASCII characters, false otherwise
bool is_str_contains_alpha(char *str)
{
    for (size_t i = 0; i < strlen(str); i++)
    {
        if (isalpha(str[i]))
        {
            return true;
        }
    }
    return false;
}

/// @brief Check if the array contains any of ASCII characters
/// @param data
/// @param data_size
/// @return true if the array contains any of ASCII characters, false otherwise
bool is_array_contains_alpha(uint_t *data, size_t data_size)
{
    for (size_t i = 0; i < data_size; i++)
    {
        if (isalpha(data[i]))
        {
            return true;
        }
    }
    return false;
}

/// @brief Convert array of integers to a byte array
/// @tparam T type of the array elements
/// @param data array of integers
/// @param data_size
/// @param new_data pointer to the result
/// @param new_size
/// @param N modulo
/// @warning The result must be freed after usage
template <typename T>
void convert_array_to_bytes_modulo(T *data, size_t data_size,
                                   byte_t **new_data, size_t *new_size,
                                   uint_t N)
{
    size_t byte_len = (hex_num_len(N) + 1) / 2; // 2 hex symbols per byte
    *new_size = data_size * byte_len;
    *new_data = ALLOC(byte_t, *new_size);
    MASSERT(*new_data != NULL, "Memory allocation failed");
    for (size_t i = 0; i < data_size; i++)
    {
        for (size_t j = 0; j < byte_len; j++)
        {
            (*new_data)[i * byte_len + j] = (data[i] >>
                                             (8 * (byte_len - 1 - j))) &
                                            0xFF;
        }
    }
}

/// @brief Convert array of integers to a byte array
/// @tparam T type of the array elements
/// @param data array of integers
/// @param data_size
/// @param new_data pointer to the result
/// @param new_size
/// @warning The result must be freed after usage
template <typename T>
void convert_array_to_bytes(T *data, size_t data_size,
                            byte_t **new_data, size_t *new_size)
{
    *new_size = data_size * sizeof(T);
    *new_data = ALLOC(byte_t, *new_size);
    MASSERT(*new_data != NULL, "Memory allocation failed");
    memcpy(*new_data, data, *new_size);
}

/// @brief Convert byte array to an array of integers
/// @tparam T type of the array elements
/// @param data byte array
/// @param data_size
/// @param new_data pointer to the result
/// @param new_size
/// @param N modulo
/// @warning The result must be freed after usage
template <typename T>
void convert_bytes_to_array_modulo(byte_t *data, size_t data_size,
                                   T **new_data, size_t *new_size,
                                   uint_t N)
{
    size_t num_len = (hex_num_len(N) + 1) / 2; // 2 hex symbols per byte
    *new_size = data_size / num_len;
    *new_data = ALLOC(T, *new_size);
    MASSERT(*new_data != NULL, "Memory allocation failed");
    for (size_t i = 0; i < *new_size; i++)
    {
        (*new_data)[i] = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            (*new_data)[i] = ((*new_data)[i] << 8) |
                             (((byte_t *)data)[i * num_len + j] & 0xFF);
        }
    }
}

/// @brief Convert byte array to an array of integers
/// @tparam T type of the array elements
/// @param data byte array
/// @param data_size
/// @param new_data pointer to the result
/// @param new_size
/// @warning The result must be freed after usage
template <typename T>
void convert_bytes_to_array(byte_t *data, size_t data_size,
                            T **new_data, size_t *new_size)
{
    *new_size = data_size / sizeof(T);
    *new_data = ALLOC(T, *new_size);
    MASSERT(*new_data != NULL, "Memory allocation failed");
    memcpy(*new_data, data, data_size);
}

/// @brief Read chunk of data from file
/// @param bytes pointer to the result
/// @param size pointer to the result
/// @param start start position in file
/// @param end end position in file
/// @param file_name
/// @warning The result must be freed after usage
void read_bin_file_chunk(byte_t **bytes, size_t *size,
                         size_t start, size_t end,
                         const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (end == 0)
    {
        end = file_size;
    }
    if (end > file_size)
    {
        end = file_size;
    }
    *size = end - start;
    *bytes = ALLOC(byte_t, *size);
    MASSERT(*bytes != NULL, "Memory allocation failed");
    fseek(file, start, SEEK_SET);
    fread(*bytes, 1, *size, file);
    fclose(file);
}

/// @brief Write chunk of data to a specified position in file
/// @param bytes data to write
/// @param size data size
/// @param start start position in file
/// @param file_name file name
void write_bin_file_chunk(const byte_t *bytes, size_t size,
                          size_t start, const char *file_name)
{
    FILE *file = fopen(file_name, "r+b");
    if (file == NULL)
    {
        file = fopen(file_name, "wb");
    }
    MASSERT(file != NULL, "Can't open file");
    fseek(file, start, SEEK_SET);
    fwrite(bytes, 1, size, file);
    fclose(file);
}

/// @brief Count chunks in the file
/// @param file_name
/// @param chunk_size
/// @return number of chunks in the file
size_t count_file_chunks(const char *file_name, size_t chunk_size)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return (file_size + chunk_size - 1) / chunk_size;
}

/// @brief Get file size
/// @param file_name
/// @return file size in bytes
size_t file_size(const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    MASSERT(file != NULL, "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return file_size;
}

void parse_hex_str(byte_t **data, size_t *data_size, const char *str)
{
    size_t str_len = strlen(str);
    *data_size = str_len / 2;
    *data = ALLOC(byte_t, *data_size);
    MASSERT(*data != NULL, "Memory allocation failed");
    for (size_t i = 0; i < *data_size; i++)
    {
        unsigned int buffer;
        sscanf(&str[i * 2], "%02x", &buffer);
        (*data)[i] = buffer;
    }
}

/*
!! Allocates memory for the result
*/
template <typename T>
void to_byte_array(T *data, size_t data_size,
                   byte_t **barray, size_t *barray_size)
{
    *barray_size = data_size * sizeof(T);
    *barray = ALLOC(byte_t, *barray_size);
    MASSERT(*barray != NULL, "Memory allocation error");
    memcpy(*barray, data, *barray_size);
}

/// @brief Padd data to the nearest chunk size
/// @param data
/// @param data_size
/// @param cap wanted chunk size
void padd_data_to_chunksize(byte_t **data, size_t *data_size, size_t cap)
{
    size_t padd_size = cap - *data_size % cap;
    if (padd_size == cap)
    {
        padd_size = 0;
    }
    std::cout << "Padd size: " << padd_size << std::endl;
    *data = REALLOC(byte_t, *data, *data_size + padd_size);
    MASSERT(*data != NULL, "Memory allocation error");
    memset(*data + *data_size, 0, padd_size);
    *data_size += padd_size;
}

void save_bmp_greyscale(float *data, size_t cols, size_t rows, char *filename)
{
    FILE *f;
    unsigned char *img = NULL;
    int filesize = 54 + 3 * cols * rows;
    if (img)
        free(img);
    img = (unsigned char *)malloc(3 * cols * rows);
    memset(img, 0, 3 * cols * rows);

    size_t x, y;
    for (x = 0; x < cols; x++)
    {
        for (y = 0; y < rows; y++)
        {
            int r = (int)((data[y * cols + x]) * 255);
            int g = (int)((data[y * cols + x]) * 255);
            int b = (int)((data[y * cols + x]) * 255);
            if (r > 255)
                r = 255;
            if (g > 255)
                g = 255;
            if (b > 255)
                b = 255;
            img[(x + y * cols) * 3 + 2] = (unsigned char)(r);
            img[(x + y * cols) * 3 + 1] = (unsigned char)(g);
            img[(x + y * cols) * 3 + 0] = (unsigned char)(b);
        }
    }

    unsigned char bmpfileheader[14] = {'B', 'M', 0, 0, 0, 0, 0,
                                       0, 0, 0, 54, 0, 0, 0};
    unsigned char bmpinfoheader[40] = {40, 0, 0, 0,  // header size
                                       0, 0, 0, 0,   // width
                                       0, 0, 0, 0,   // height
                                       1, 0, 24, 0}; // planes, bits per pixel
    unsigned char bmppad[3] = {0, 0, 0};

    bmpfileheader[2] = (unsigned char)(filesize);
    bmpfileheader[3] = (unsigned char)(filesize >> 8);
    bmpfileheader[4] = (unsigned char)(filesize >> 16);
    bmpfileheader[5] = (unsigned char)(filesize >> 24);

    bmpinfoheader[4] = (unsigned char)(cols);
    bmpinfoheader[5] = (unsigned char)(cols >> 8);
    bmpinfoheader[6] = (unsigned char)(cols >> 16);
    bmpinfoheader[7] = (unsigned char)(cols >> 24);
    bmpinfoheader[8] = (unsigned char)(rows);
    bmpinfoheader[9] = (unsigned char)(rows >> 8);
    bmpinfoheader[10] = (unsigned char)(rows >> 16);
    bmpinfoheader[11] = (unsigned char)(rows >> 24);

    f = fopen(filename, "wb");
    fwrite(bmpfileheader, 1, 14, f);
    fwrite(bmpinfoheader, 1, 40, f);
    for (size_t i = 0; i < rows; i++)
    {
        fwrite(img + (cols * (rows - i - 1) * 3), 3, cols, f);
        fwrite(bmppad, 1, (4 - (cols * 3) % 4) % 4, f);
    }
    fclose(f);
}

// ===--- RSA CIPHER ---========================================================
#define __RSA_CIPHER

/// @brief RSA modulo
/// @param p first prime number
/// @param q second prime number
/// @return RSA modulo
uint_t rsa_N(uint_t p, uint_t q)
{
    MASSERT(is_prime(p), "p must be prime");
    MASSERT(is_prime(q), "q must be prime");
    return p * q;
}

/// @brief RSA t parameter
/// @param p first prime number
/// @param q second prime number
/// @return RSA t parameter (p - 1) * (q - 1)
uint_t rsa_t(uint_t p, uint_t q)
{
    MASSERT(is_prime(p), "p must be prime");
    MASSERT(is_prime(q), "q must be prime");
    return (p - 1) * (q - 1);
}

/// @brief Generate RSA encryption key
/// @param t RSA t parameter
/// @return RSA encryption key
uint_t rsa_public_key(uint_t t)
{
    std::vector<uint_t> lst;
    for (uint_t i = 2; i < t - 1; i++)
    {
        if (is_prime(i) && t % i != 0)
        {
            lst.push_back(i);
        }
    }
    return lst[rand() % lst.size()];
}

/// @brief Generate RSA decryption key
/// @param cif_key RSA encryption key
/// @param t RSA t parameter
/// @return RSA decryption key
uint_t rsa_private_key(uint_t cif_key, uint_t t)
{
    for (uint_t i = 1; i < t; i++)
    {
        if ((cif_key * i) % t == 1)
        {
            return i;
        }
    }
    return -1;
}

/// @brief RSA encrypt
/// @tparam T type of the data
/// @param x data
/// @param key RSA encryption key
/// @param N modulo
/// @return encrypted data
template <typename T>
uint_t rsa_encrypt(T x, uint_t key, uint_t N)
{
    return pow_mod(x, key, N);
}

/// @brief RSA array encrypt
/// @tparam T type of the data
/// @param data array of data
/// @param data_size
/// @param cif pointer to the result
/// @param cif_size pointer to the result
/// @param key RSA encryption key
/// @param N modulo
/// @warning The result must be freed after usage
template <typename T>
void rsa_encrypt(T *data, size_t data_size,
                 uint_t **cif, size_t *cif_size,
                 uint_t key, uint_t N)
{
    uint_t *res = ALLOC(uint_t, 2 * data_size);
    MASSERT(res != NULL, "Memory allocation failed");

    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = rsa_encrypt(data[i], key, N);
    }
    *cif = res;
    *cif_size = data_size;
}

/// @brief RSA decrypt
/// @param x encrypted data
/// @param key RSA decryption key
/// @param N modulo
/// @return decrypted data
uint_t rsa_decrypt(uint_t x, uint_t key, uint_t N)
{
    return pow_mod(x, key, N);
}

/// @brief RSA array decrypt
/// @tparam T type of the data
/// @param cif array of encrypted data
/// @param cif_size
/// @param data pointer to the result
/// @param data_size pointer to the result
/// @param key RSA decryption key
/// @param N modulo
/// @warning The result must be freed after usage
template <typename T>
void rsa_decrypt(uint_t *cif, size_t cif_size,
                 T **data, size_t *data_size,
                 uint_t key, uint_t N)
{
    T *res = ALLOC(T, cif_size);
    MASSERT(res != NULL, "Memory allocation failed");

    for (size_t i = 0; i < cif_size; i++)
    {
        res[i] = rsa_decrypt(cif[i], key, N);
    }
    *data = res;
    *data_size = cif_size;
}

// ===--- ELGAMAL CIPHER ---====================================================
#define __ELGAMAL_CIPHER

/// @brief Generate ElGamal session key
/// @param p modulo
/// @return ElGamal session key
uint_t __elg_session_key_x(uint_t p)
{
    return rand() % (p - 1) + 1;
}

/// @brief ElGamal y parameter
/// @param g primitive root modulo p
/// @param x ElGamal session key
/// @param p modulo
/// @return ElGamal y parameter
uint_t __elg_y(uint_t g, uint_t x, uint_t p)
{
    return pow_mod(g, x, p);
}

/// @brief Make ElGamal private key
/// @param key_x pointer to the result
/// @param p modulo
void elg_private_key(uint_t *key_x, uint_t p)
{
    *key_x = __elg_session_key_x(p);
}

/// @brief Make ElGamal public key
/// @param key_y ElGamal y parameter, pointer to the result
/// @param key_g generator, pointer to the result
/// @param x ElGamal session key
/// @param p modulo
void elg_public_key(uint_t *key_y, uint_t *key_g, uint_t x, uint_t p)
{
    *key_g = primitive_root_mod(p);
    *key_y = __elg_y(*key_g, x, p);
}

/// @brief ElGamal encrypt
/// @param a pointer to the result
/// @param b pointer to the result
/// @param m data
/// @param key_y ElGamal y parameter
/// @param key_g generator
/// @param p modulo
void elg_encrypt(uint_t *a, uint_t *b, uint_t m, uint_t key_y, uint_t key_g, uint_t p)
{
    uint_t k = __elg_session_key_x(p);
    *a = pow_mod(key_g, k, p);
    *b = (m * pow_mod(key_y, k, p)) % p;
}

/// @brief ElGamal encrypt
/// @param data array of data
/// @param data_size
/// @param cif pointer to the result, array of encrypted data
/// @param cif_size
/// @param key_y ElGamal y parameter
/// @param key_g generator
/// @param p modulo
/// @warning The result must be freed after usage
void elg_encrypt(uint_t *data, size_t data_size,
                 uint_t **cif, size_t *cif_size,
                 uint_t key_y, uint_t key_g, uint_t p)
{
    uint_t *res = ALLOC(uint_t, data_size << 1);
    MASSERT(res != NULL, "Memory allocation failed");

    uint_t a, b;
    for (size_t i = 0; i < data_size; i++)
    {
        elg_encrypt(&a, &b, data[i], key_y, key_g, p);
        res[i << 1] = a;
        res[(i << 1) + 1] = b;
    }
    *cif = res;
    *cif_size = data_size << 1;
}

/// @brief ElGamal decrypt
/// @param a
/// @param b
/// @param key_x ElGamal session key
/// @param p modulo
/// @return decrypted data
uint_t elg_decrypt(uint_t a, uint_t b, uint_t key_x, uint_t p)
{
    return (b * pow_mod(a, p - 1 - key_x, p)) % p;
}

/// @brief ElGamal decrypt
/// @param cif array of encrypted data
/// @param cif_size
/// @param data pointer to the result
/// @param data_size pointer to the result
/// @param key_x ElGamal session key
/// @param p modulo
/// @warning The result must be freed after usage
void elg_dcif(uint_t *cif, size_t cif_size,
              uint_t **data, size_t *data_size,
              uint_t key_x, uint_t p)
{
    uint_t *res = ALLOC(uint_t, cif_size >> 1);
    MASSERT(res != NULL, "Memory allocation failed");

    for (size_t i = 0; i < cif_size; i += 2)
    {
        res[i >> 1] = elg_decrypt(cif[i], cif[i + 1], key_x, p);
    }
    *data = res;
    *data_size = cif_size >> 1;
}

// ===--- ELGAMAL SIGNATURE ---=================================================
#define __ELGAMAL_SIGNATURE

/// @brief ElGamal signature k parameter
/// @param p modulo
/// @return ElGamal signature k parameter
uint_t __elgsig_k(uint_t p)
{
    return coprime(p - 1);
}

/// @brief ElGamal signature a parameter
/// @param g generator
/// @param k ElGamal signature k parameter
/// @param p modulo
/// @return ElGamal signature a parameter
uint_t __elgsig_a(uint_t g, uint_t k, uint_t p)
{
    return pow_mod(g, k, p);
}

/// @brief ElGamal signature reverse k parameter
/// @param k ElGamal signature k parameter
/// @param p modulo
/// @return ElGamal signature reverse k parameter
uint_t __elgsig_reverse_k(uint_t k, uint_t p)
{
    return multiplicative_inverse(k, p - 1);
}

/// @brief ElGamal signature b parameter
/// @param m data
/// @param k ElGamal signature k parameter
/// @param x ElGamal session key
/// @param a ElGamal signature a parameter
/// @param p modulo
/// @return ElGamal signature b parameter
uint_t __elgsig_b(uint_t m, uint_t k, uint_t x, uint_t a, uint_t p)
{
    uint_t mmod = (__elgsig_reverse_k(k, p) * (m - x * a)) % (p - 1);
    // 'C' peculiarity about mod operation:
    return mmod >= 0 ? mmod : mmod + p - 1;
}

/// @brief ElGamal signature
/// @param a pointer to the result
/// @param b pointer to the result
/// @param key_x ElGamal session key
/// @param key_g generator
/// @param p modulo
/// @param m data
void elgsig_sign(uint_t *a, uint_t *b,
                 uint_t key_x, uint_t key_g,
                 uint_t p, uint_t m)
{
    uint_t k = __elgsig_k(p);
    *a = __elgsig_a(key_g, k, p);
    *b = __elgsig_b(m, k, key_x, *a, p);
}

/// @brief ElGamal signature
/// @param data array of data
/// @param data_size
/// @param cif pointer to the result, array of encrypted data
/// @param cif_size
/// @param key_y ElGamal y parameter
/// @param key_g generator
/// @param p modulo
/// @warning The result must be freed after usage
void elgsig_sign(uint_t *data, size_t data_size,
                 uint_t **cif, size_t *cif_size,
                 uint_t key_y, uint_t key_g, uint_t p)
{
    uint_t *res = ALLOC(uint_t, data_size << 1);
    MASSERT(res != NULL, "Memory allocation failed");

    uint_t a, b;
    for (size_t i = 0; i < data_size; i++)
    {
        elgsig_sign(&a, &b, key_y, key_g, p, data[i]);
        res[i << 1] = a;
        res[(i << 1) + 1] = b;
    }
    *cif = res;
    *cif_size = data_size << 1;
}

/// @brief ElGamal signature check
/// @param key_y ElGamal y parameter
/// @param key_g generator
/// @param a ElGamal signature a parameter
/// @param b ElGamal signature b parameter
/// @param p modulo
/// @param m data
/// @return true if the signature is valid, false otherwise
bool elgsig_check(uint_t key_y, uint_t key_g,
                  uint_t a, uint_t b, uint_t p, uint_t m)
{
    return (pow_mod(key_y, a, p) * pow_mod(a, b, p)) % p == pow_mod(
                                                                key_g, m, p);
}

/// @brief ElGamal signature check
/// @param cif array of encrypted data
/// @param cif_size
/// @param key_y ElGamal y parameter
/// @param key_g generator
/// @param p modulo
/// @param data array of data
/// @param data_size
/// @return true if the signature is valid, false otherwise
bool elgsig_check(uint_t *cif, size_t cif_size,
                  uint_t key_y, uint_t key_g, uint_t p,
                  uint_t *data, size_t data_size)
{
    if (cif_size != data_size << 1)
    {
        return false;
    }
    for (size_t i = 0; i < cif_size; i += 2)
    {
        if (!elgsig_check(key_y, key_g, cif[i], cif[i + 1], p, data[i >> 1]))
        {
            return false;
        }
    }
    return true;
}

// ===--- DES CIPHER ---========================================================
#define __DES_CIPHER

#define DES_ENCRYPTION_MODE 1
#define DES_DECRYPTION_MODE 0

typedef struct des_key_set
{
    byte_t k[8];
    byte_t c[4];
    byte_t d[4];
} des_key_set;

byte_t __des_initial_key_permutaion[] = {0x39, 0x31, 0x29, 0x21,
                                         0x19, 0x11, 0x09, 0x01,
                                         0x3A, 0x32, 0x2A, 0x22,
                                         0x1A, 0x12, 0x0A, 0x02,
                                         0x3B, 0x33, 0x2B, 0x23,
                                         0x1B, 0x13, 0x0B, 0x03,
                                         0x3C, 0x34, 0x2C, 0x24,
                                         0x3F, 0x37, 0x2F, 0x27,
                                         0x1F, 0x17, 0x0F, 0x07,
                                         0x3E, 0x36, 0x2E, 0x26,
                                         0x1E, 0x16, 0x0E, 0x06,
                                         0x3D, 0x35, 0x2D, 0x25,
                                         0x1D, 0x15, 0x0D, 0x05,
                                         0x1C, 0x14, 0x0C, 0x04};

// Initial permutation (IP)
byte_t __des_initial_message_permutation[] = {0x3A, 0x32, 0x2A, 0x22,
                                              0x1A, 0x12, 0x0A, 0x02,
                                              0x3C, 0x34, 0x2C, 0x24,
                                              0x1C, 0x14, 0x0C, 0x04,
                                              0x3E, 0x36, 0x2E, 0x26,
                                              0x1E, 0x16, 0x0E, 0x06,
                                              0x40, 0x38, 0x30, 0x28,
                                              0x20, 0x18, 0x10, 0x08,
                                              0x39, 0x31, 0x29, 0x21,
                                              0x19, 0x11, 0x09, 0x01,
                                              0x3B, 0x33, 0x2B, 0x23,
                                              0x1B, 0x13, 0x0B, 0x03,
                                              0x3D, 0x35, 0x2D, 0x25,
                                              0x1D, 0x15, 0x0D, 0x05,
                                              0x3F, 0x37, 0x2F, 0x27,
                                              0x1F, 0x17, 0x0F, 0x07};

// 17
int __des_key_shift_sizes[] = {-1,
                               1, 1, 2, 2, 2, 2, 2, 2,
                               1, 2, 2, 2, 2, 2, 2, 1};

// Subkey permutation
byte_t __des_sub_key_permutation[] = {0x0E, 0x11, 0x0B, 0x18, 0x01, 0x05,
                                      0x03, 0x1C, 0x0F, 0x06, 0x15, 0x0A,
                                      0x17, 0x13, 0x0C, 0x04, 0x1A, 0x08,
                                      0x10, 0x07, 0x1B, 0x14, 0x0D, 0x02,
                                      0x29, 0x34, 0x1F, 0x25, 0x2F, 0x37,
                                      0x1E, 0x28, 0x33, 0x2D, 0x21, 0x30,
                                      0x2C, 0x31, 0x27, 0x38, 0x22, 0x35,
                                      0x2E, 0x2A, 0x32, 0x24, 0x1D, 0x20};

// Expansion table (E)
byte_t __des_message_expansion[] = {0x20, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                    0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
                                    0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x01};

// S_i transformation tables
byte_t __des_S1[] = {0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
                     0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07,
                     0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01,
                     0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08,
                     0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B,
                     0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00,
                     0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07,
                     0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D};

byte_t __des_S2[] = {0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04,
                     0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A,
                     0x03, 0x0D, 0x04, 0x07, 0x0F, 0x02, 0x08, 0x0E,
                     0x0C, 0x00, 0x01, 0x0A, 0x06, 0x09, 0x0B, 0x05,
                     0x00, 0x0E, 0x07, 0x0B, 0x0A, 0x04, 0x0D, 0x01,
                     0x05, 0x08, 0x0C, 0x06, 0x09, 0x03, 0x02, 0x0F,
                     0x0D, 0x08, 0x0A, 0x01, 0x03, 0x0F, 0x04, 0x02,
                     0x0B, 0x06, 0x07, 0x0C, 0x00, 0x05, 0x0E, 0x09};

byte_t __des_S3[] = {0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05,
                     0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08,
                     0x0D, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0A,
                     0x02, 0x08, 0x05, 0x0E, 0x0C, 0x0B, 0x0F, 0x01,
                     0x0D, 0x06, 0x04, 0x09, 0x08, 0x0F, 0x03, 0x00,
                     0x0B, 0x01, 0x02, 0x0C, 0x05, 0x0A, 0x0E, 0x07,
                     0x01, 0x0A, 0x0D, 0x00, 0x06, 0x09, 0x08, 0x07,
                     0x04, 0x0F, 0x0E, 0x03, 0x0B, 0x05, 0x02, 0x0C};

byte_t __des_S4[] = {0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A,
                     0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F,
                     0x0D, 0x08, 0x0B, 0x05, 0x06, 0x0F, 0x00, 0x03,
                     0x04, 0x07, 0x02, 0x0C, 0x01, 0x0A, 0x0E, 0x09,
                     0x0A, 0x06, 0x09, 0x00, 0x0C, 0x0B, 0x07, 0x0D,
                     0x0F, 0x01, 0x03, 0x0E, 0x05, 0x02, 0x08, 0x04,
                     0x03, 0x0F, 0x00, 0x06, 0x0A, 0x01, 0x0D, 0x08,
                     0x09, 0x04, 0x05, 0x0B, 0x0C, 0x07, 0x02, 0x0E};

byte_t __des_S5[] = {0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06,
                     0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09,
                     0x0E, 0x0B, 0x02, 0x0C, 0x04, 0x07, 0x0D, 0x01,
                     0x05, 0x00, 0x0F, 0x0A, 0x03, 0x09, 0x08, 0x06,
                     0x04, 0x02, 0x01, 0x0B, 0x0A, 0x0D, 0x07, 0x08,
                     0x0F, 0x09, 0x0C, 0x05, 0x06, 0x03, 0x00, 0x0E,
                     0x0B, 0x08, 0x0C, 0x07, 0x01, 0x0E, 0x02, 0x0D,
                     0x06, 0x0F, 0x00, 0x09, 0x0A, 0x04, 0x05, 0x03};

byte_t __des_S6[] = {0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08,
                     0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B,
                     0x0A, 0x0F, 0x04, 0x02, 0x07, 0x0C, 0x09, 0x05,
                     0x06, 0x01, 0x0D, 0x0E, 0x00, 0x0B, 0x03, 0x08,
                     0x09, 0x0E, 0x0F, 0x05, 0x02, 0x08, 0x0C, 0x03,
                     0x07, 0x00, 0x04, 0x0A, 0x01, 0x0D, 0x0B, 0x06,
                     0x04, 0x03, 0x02, 0x0C, 0x09, 0x05, 0x0F, 0x0A,
                     0x0B, 0x0E, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0D};

byte_t __des_S7[] = {0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D,
                     0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01,
                     0x0D, 0x00, 0x0B, 0x07, 0x04, 0x09, 0x01, 0x0A,
                     0x0E, 0x03, 0x05, 0x0C, 0x02, 0x0F, 0x08, 0x06,
                     0x01, 0x04, 0x0B, 0x0D, 0x0C, 0x03, 0x07, 0x0E,
                     0x0A, 0x0F, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02,
                     0x06, 0x0B, 0x0D, 0x08, 0x01, 0x04, 0x0A, 0x07,
                     0x09, 0x05, 0x00, 0x0F, 0x0E, 0x02, 0x03, 0x0C};

byte_t __des_S8[] = {0x0D, 0x02, 0x08, 0x04, 0x06, 0x0F, 0x0B, 0x01,
                     0x0A, 0x09, 0x03, 0x0E, 0x05, 0x00, 0x0C, 0x07,
                     0x01, 0x0F, 0x0D, 0x08, 0x0A, 0x03, 0x07, 0x04,
                     0x0C, 0x05, 0x06, 0x0B, 0x00, 0x0E, 0x09, 0x02,
                     0x07, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x0E, 0x02,
                     0x00, 0x06, 0x0A, 0x0D, 0x0F, 0x03, 0x05, 0x08,
                     0x02, 0x01, 0x0E, 0x07, 0x04, 0x0A, 0x08, 0x0D,
                     0x0F, 0x0C, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0B};

// Permutation table (P)
byte_t __des_right_sub_msg_permut[] = {0x10, 0x07, 0x14, 0x15,
                                       0x1D, 0x0C, 0x1C, 0x11,
                                       0x01, 0x0F, 0x17, 0x1A,
                                       0x05, 0x12, 0x1F, 0x0A,
                                       0x02, 0x08, 0x18, 0x0E,
                                       0x20, 0x1B, 0x03, 0x09,
                                       0x13, 0x0D, 0x1E, 0x06,
                                       0x16, 0x0B, 0x04, 0x19};

// Final permutation (IP^-1)
byte_t __des_final_msg_permut[] = {0x28, 0x08, 0x30, 0x10,
                                   0x38, 0x18, 0x40, 0x20,
                                   0x27, 0x07, 0x2F, 0x0F,
                                   0x37, 0x17, 0x3F, 0x1F,
                                   0x26, 0x06, 0x2E, 0x0E,
                                   0x36, 0x16, 0x3E, 0x1E,
                                   0x25, 0x05, 0x2D, 0x0D,
                                   0x35, 0x15, 0x3D, 0x1D,
                                   0x24, 0x04, 0x2C, 0x0C,
                                   0x34, 0x14, 0x3C, 0x1C,
                                   0x23, 0x03, 0x2B, 0x0B,
                                   0x33, 0x13, 0x3B, 0x1B,
                                   0x22, 0x02, 0x2A, 0x0A,
                                   0x32, 0x12, 0x3A, 0x1A,
                                   0x21, 0x01, 0x29, 0x09,
                                   0x31, 0x11, 0x39, 0x19};

/// @brief Check if the key is weak in terms of DES
/// @param key
/// @return true if the key is weak, false otherwise
bool __des_is_key_weak(byte_t *key)
{
    byte_t weak_key1[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    byte_t weak_key2[] = {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE};
    byte_t weak_key3[] = {0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1};
    byte_t weak_key4[] = {0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E};

    return memcmp(key, weak_key1, 8) == 0 ||
           memcmp(key, weak_key2, 8) == 0 ||
           memcmp(key, weak_key3, 8) == 0 ||
           memcmp(key, weak_key4, 8) == 0;
}

/// @brief Check if the key is semi-weak in terms of DES
/// @param key
/// @return true if the key is semi-weak, false otherwise
bool __des_is_key_semi_weak(byte_t *key)
{
    byte_t s_weak_key_01[] = {0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE};
    byte_t s_weak_key_02[] = {0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01};
    byte_t s_weak_key_03[] = {0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1};
    byte_t s_weak_key_04[] = {0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E};
    byte_t s_weak_key_05[] = {0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1};
    byte_t s_weak_key_06[] = {0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01};
    byte_t s_weak_key_07[] = {0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE};
    byte_t s_weak_key_08[] = {0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E};
    byte_t s_weak_key_09[] = {0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E};
    byte_t s_weak_key_10[] = {0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01};
    byte_t s_weak_key_11[] = {0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1};
    byte_t s_weak_key_12[] = {0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE};

    return memcmp(key, s_weak_key_01, 8) == 0 ||
           memcmp(key, s_weak_key_02, 8) == 0 ||
           memcmp(key, s_weak_key_03, 8) == 0 ||
           memcmp(key, s_weak_key_04, 8) == 0 ||
           memcmp(key, s_weak_key_05, 8) == 0 ||
           memcmp(key, s_weak_key_06, 8) == 0 ||
           memcmp(key, s_weak_key_07, 8) == 0 ||
           memcmp(key, s_weak_key_08, 8) == 0 ||
           memcmp(key, s_weak_key_09, 8) == 0 ||
           memcmp(key, s_weak_key_10, 8) == 0 ||
           memcmp(key, s_weak_key_11, 8) == 0 ||
           memcmp(key, s_weak_key_12, 8) == 0;
}

/// @brief Check if the key is acceptable in terms of DES
/// @param key
/// @return true if the key is acceptable, false otherwise
bool __des_is_key_acceptable(byte_t *key)
{
    return !__des_is_key_weak(key) && !__des_is_key_semi_weak(key);
}

/// @brief Generate 16(+1) sub keys from the main key
/// @param main_key 64 bit key
/// @param key_sets array of (+1)16 key sets
void __des_generate_sub_keys(byte_t *main_key, des_key_set *key_sets)
{
    int i, j;
    int shift_size;
    byte_t shift_byte,
        first_shift_bits,
        second_shift_bits,
        third_shift_bits,
        fourth_shift_bits;

    // Zero out first key set's k
    for (i = 0; i < 8; i++)
    {
        key_sets[0].k[i] = 0;
    }

    for (j = 1; j < 17; j++)
    {
        for (i = 0; i < 8; i++)
        {
            key_sets[j].k[i] = 0;
        }
    }

    // Generate first key set's k
    for (i = 0; i < 56; i++)
    {
        shift_size = __des_initial_key_permutaion[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= main_key[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);

        key_sets[0].k[i / 8] |= (shift_byte >> i % 8);
    }

    // Copy first 3 bytes of k to c
    for (i = 0; i < 3; i++)
    {
        key_sets[0].c[i] = key_sets[0].k[i];
    }

    // Copy last byte of k to c and mask it
    key_sets[0].c[3] = key_sets[0].k[3] & 0xF0;

    // Copy last 4 bytes of k to d
    for (i = 0; i < 3; i++)
    {
        key_sets[0].d[i] = (key_sets[0].k[i + 3] & 0x0F) << 4;
        key_sets[0].d[i] |= (key_sets[0].k[i + 4] & 0xF0) >> 4;
    }

    // Mask last byte of d
    key_sets[0].d[3] = (key_sets[0].k[6] & 0x0F) << 4;

    // Generate 16 sub keys
    for (i = 1; i < 17; i++)
    {
        // Copy previous key set to current
        for (j = 0; j < 4; j++)
        {
            key_sets[i].c[j] = key_sets[i - 1].c[j];
            key_sets[i].d[j] = key_sets[i - 1].d[j];
        }

        shift_size = __des_key_shift_sizes[i];
        if (shift_size == 1)
        {
            shift_byte = 0x80;
        }
        else
        {
            shift_byte = 0xC0;
        }

        // Process C
        first_shift_bits = shift_byte & key_sets[i].c[0];
        second_shift_bits = shift_byte & key_sets[i].c[1];
        third_shift_bits = shift_byte & key_sets[i].c[2];
        fourth_shift_bits = shift_byte & key_sets[i].c[3];

        key_sets[i].c[0] <<= shift_size;
        key_sets[i].c[0] |= (second_shift_bits >> (8 - shift_size));

        key_sets[i].c[1] <<= shift_size;
        key_sets[i].c[1] |= (third_shift_bits >> (8 - shift_size));

        key_sets[i].c[2] <<= shift_size;
        key_sets[i].c[2] |= (fourth_shift_bits >> (8 - shift_size));

        key_sets[i].c[3] <<= shift_size;
        key_sets[i].c[3] |= (first_shift_bits >> (4 - shift_size));

        // Process D
        first_shift_bits = shift_byte & key_sets[i].d[0];
        second_shift_bits = shift_byte & key_sets[i].d[1];
        third_shift_bits = shift_byte & key_sets[i].d[2];
        fourth_shift_bits = shift_byte & key_sets[i].d[3];

        key_sets[i].d[0] <<= shift_size;
        key_sets[i].d[0] |= (second_shift_bits >> (8 - shift_size));

        key_sets[i].d[1] <<= shift_size;
        key_sets[i].d[1] |= (third_shift_bits >> (8 - shift_size));

        key_sets[i].d[2] <<= shift_size;
        key_sets[i].d[2] |= (fourth_shift_bits >> (8 - shift_size));

        key_sets[i].d[3] <<= shift_size;
        key_sets[i].d[3] |= (first_shift_bits >> (4 - shift_size));

        // Merge C and D to generate K
        for (j = 0; j < 48; j++)
        {
            shift_size = __des_sub_key_permutation[j];
            if (shift_size <= 28)
            {
                shift_byte = 0x80 >> ((shift_size - 1) % 8);
                shift_byte &= key_sets[i].c[(shift_size - 1) / 8];
                shift_byte <<= ((shift_size - 1) % 8);
            }
            else
            {
                shift_byte = 0x80 >> ((shift_size - 29) % 8);
                shift_byte &= key_sets[i].d[(shift_size - 29) / 8];
                shift_byte <<= ((shift_size - 29) % 8);
            }

            key_sets[i].k[j / 8] |= (shift_byte >> j % 8);
        }
    }
}

/// @brief Process a 64 bit block of data using DES
/// @param data_block
/// @param processed_block
/// @param key_sets array of 16(+1) key sets
/// @param mode 1 for encryption, 0 for decryption
void __des_process_data_block(byte_t *data_block,
                              byte_t *processed_block,
                              des_key_set *key_sets,
                              int mode)
{
    int i, k;
    int shift_size;
    byte_t shift_byte;

    byte_t initial_permutation[8];
    memset(initial_permutation, 0, 8);
    memset(processed_block, 0, 8);

    // Initial permutation
    for (i = 0; i < 64; i++)
    {
        shift_size = __des_initial_message_permutation[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= data_block[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);

        initial_permutation[i / 8] |= (shift_byte >> i % 8);
    }

    // Split message into two 32-bit pieces
    byte_t l[4], r[4];
    for (i = 0; i < 4; i++)
    {
        l[i] = initial_permutation[i];
        r[i] = initial_permutation[i + 4];
    }

    byte_t ln[4], rn[4], er[6], ser[4];

    // 16 rounds of Feistel network
    int key_index;
    for (k = 1; k <= 16; k++)
    {
        memcpy(ln, r, 4);
        memset(er, 0, 6);

        // Expansion permutation (E)
        for (i = 0; i < 48; i++)
        {
            shift_size = __des_message_expansion[i];
            shift_byte = 0x80 >> ((shift_size - 1) % 8);
            shift_byte &= r[(shift_size - 1) / 8];
            shift_byte <<= ((shift_size - 1) % 8);

            er[i / 8] |= (shift_byte >> i % 8);
        }

        // If decryption mode, use keys in reverse order
        if (mode == DES_DECRYPTION_MODE)
        {
            key_index = 17 - k;
        }
        else
        {
            key_index = k;
        }

        // XOR with key
        for (i = 0; i < 6; i++)
        {
            er[i] ^= key_sets[key_index].k[i];
        }

        byte_t row, column;

        for (i = 0; i < 4; i++)
        {
            ser[i] = 0;
        }

        // S-Box substitution

        // 0000 0000 0000 0000 0000 0000
        // rccc crrc cccr rccc crrc cccr

        // Byte 1
        row = 0;
        row |= ((er[0] & 0x80) >> 6);
        row |= ((er[0] & 0x04) >> 2);

        column = 0;
        column |= ((er[0] & 0x78) >> 3);

        ser[0] |= ((byte_t)__des_S1[row * 16 + column] << 4);

        row = 0;
        row |= (er[0] & 0x02);
        row |= ((er[1] & 0x10) >> 4);

        column = 0;
        column |= ((er[0] & 0x01) << 3);
        column |= ((er[1] & 0xE0) >> 5);

        ser[0] |= (byte_t)__des_S2[row * 16 + column];

        // Byte 2
        row = 0;
        row |= ((er[1] & 0x08) >> 2);
        row |= ((er[2] & 0x40) >> 6);

        column = 0;
        column |= ((er[1] & 0x07) << 1);
        column |= ((er[2] & 0x80) >> 7);

        ser[1] |= ((byte_t)__des_S3[row * 16 + column] << 4);

        row = 0;
        row |= ((er[2] & 0x20) >> 4);
        row |= (er[2] & 0x01);

        column = 0;
        column |= ((er[2] & 0x1E) >> 1);

        ser[1] |= (byte_t)__des_S4[row * 16 + column];

        // Byte 3
        row = 0;
        row |= ((er[3] & 0x80) >> 6);
        row |= ((er[3] & 0x04) >> 2);

        column = 0;
        column |= ((er[3] & 0x78) >> 3);

        ser[2] |= ((byte_t)__des_S5[row * 16 + column] << 4);

        row = 0;
        row |= (er[3] & 0x02);
        row |= ((er[4] & 0x10) >> 4);

        column = 0;
        column |= ((er[3] & 0x01) << 3);
        column |= ((er[4] & 0xE0) >> 5);

        ser[2] |= (byte_t)__des_S6[row * 16 + column];

        // Byte 4
        row = 0;
        row |= ((er[4] & 0x08) >> 2);
        row |= ((er[5] & 0x40) >> 6);

        column = 0;
        column |= ((er[4] & 0x07) << 1);
        column |= ((er[5] & 0x80) >> 7);

        ser[3] |= ((byte_t)__des_S7[row * 16 + column] << 4);

        row = 0;
        row |= ((er[5] & 0x20) >> 4);
        row |= (er[5] & 0x01);

        column = 0;
        column |= ((er[5] & 0x1E) >> 1);

        ser[3] |= (byte_t)__des_S8[row * 16 + column];

        for (i = 0; i < 4; i++)
        {
            rn[i] = 0;
        }

        // Straight permutation (P)
        for (i = 0; i < 32; i++)
        {
            shift_size = __des_right_sub_msg_permut[i];
            shift_byte = 0x80 >> ((shift_size - 1) % 8);
            shift_byte &= ser[(shift_size - 1) / 8];
            shift_byte <<= ((shift_size - 1) % 8);

            rn[i / 8] |= (shift_byte >> i % 8);
        }

        for (i = 0; i < 4; i++)
        {
            rn[i] ^= l[i];
        }

        for (i = 0; i < 4; i++)
        {
            l[i] = ln[i];
            r[i] = rn[i];
        }
    }

    // Combine R and L, pre-end permutation
    byte_t pre_end_permutation[8];
    for (i = 0; i < 4; i++)
    {
        pre_end_permutation[i] = r[i];
        pre_end_permutation[4 + i] = l[i];
    }

    for (i = 0; i < 64; i++)
    {
        shift_size = __des_final_msg_permut[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= pre_end_permutation[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);

        processed_block[i / 8] |= (shift_byte >> i % 8);
    }
}

/// @brief Encrypt a 64 bit block of data using DES
/// @param data_block
/// @param processed_block
/// @param key_sets array of 16(+1) key sets
void __des_encrypt_block(byte_t *data_block,
                         byte_t *processed_block,
                         des_key_set *key_sets)
{
    __des_process_data_block(data_block,
                             processed_block,
                             key_sets,
                             DES_ENCRYPTION_MODE);
}

/// @brief Decrypt a 64 bit block of data using DES
/// @param data_block
/// @param processed_block
/// @param key_sets array of 16(+1) key sets
void __des_decrypt_block(byte_t *data_block,
                         byte_t *processed_block,
                         des_key_set *key_sets)
{
    __des_process_data_block(data_block,
                             processed_block,
                             key_sets,
                             DES_DECRYPTION_MODE);
}

/// @brief Generate a random 64 bit key
/// @param key
void des_key(byte_t *key)
{
    do
    {
        int i;
        for (i = 0; i < 8; i++)
        {
            key[i] = rand() % 255;
        }
    } while (!__des_is_key_acceptable(key));
}

/// @brief Encrypt data using DES
/// @param data
/// @param data_size
/// @param enc_data
/// @param enc_data_size
/// @param des_key 64 bit key
void des_encrypt(byte_t *data, size_t data_size,
                 byte_t *enc_data, size_t *enc_data_size,
                 byte_t *des_key)
{
    MASSERT(data != NULL, "data cannot be NULL");
    MASSERT(data_size > 0, "data_size must be greater than 0");
    MASSERT(data_size % 8 == 0, "data_size must be a multiple of 8");
    MASSERT(enc_data != NULL, "enc_data cannot be NULL");
    MASSERT(des_key != NULL, "des_key cannot be NULL");

    byte_t *data_block = ALLOC(byte_t, 8);
    MASSERT(data_block != NULL, "Memory allocation failed");

    byte_t *processed_block = ALLOC(byte_t, 8);
    MASSERT(processed_block != NULL, "Memory allocation failed");

    des_key_set *key_sets = ALLOC(des_key_set, 17);
    MASSERT(key_sets != NULL, "Memory allocation failed");

    __des_generate_sub_keys(des_key, key_sets);

    unsigned long number_of_blocks = data_size / 8 + (data_size % 8 ? 1 : 0);

    for (unsigned long block_count = 0;
         block_count < number_of_blocks;
         block_count++)
    {
        for (int i = 0; i < 8; i++)
        {
            data_block[i] = data[block_count * 8 + i];
        }

        __des_encrypt_block(data_block, processed_block, key_sets);

        for (int i = 0; i < 8; i++)
        {
            enc_data[block_count * 8 + i] = processed_block[i];
        }
    }

    *enc_data_size = data_size;
    FREE(data_block);
    FREE(processed_block);
    FREE(key_sets);
}

/// @brief Decrypt data using DES
/// @param data
/// @param data_size
/// @param dec_data
/// @param dec_data_size
/// @param des_key 64 bit key
void des_decrypt(byte_t *data, size_t data_size,
                 byte_t *dec_data, size_t *dec_data_size,
                 byte_t *des_key)
{
    MASSERT(data != NULL, "data cannot be NULL");
    MASSERT(data_size > 0, "data_size must be greater than 0");
    MASSERT(data_size % 8 == 0, "data_size must be a multiple of 8");
    MASSERT(dec_data != NULL, "dec_data cannot be NULL");
    MASSERT(des_key != NULL, "des_key cannot be NULL");

    byte_t *data_block = ALLOC(byte_t, 8);
    MASSERT(data_block != NULL, "Memory allocation failed");

    byte_t *processed_block = ALLOC(byte_t, 8);
    MASSERT(processed_block != NULL, "Memory allocation failed");

    des_key_set *key_sets = ALLOC(des_key_set, 17);
    MASSERT(key_sets != NULL, "Memory allocation failed");

    __des_generate_sub_keys(des_key, key_sets);

    unsigned long number_of_blocks = data_size / 8 + (data_size % 8 ? 1 : 0);

    for (unsigned long block_count = 0;
         block_count < number_of_blocks;
         block_count++)
    {
        for (int i = 0; i < 8; i++)
        {
            data_block[i] = data[block_count * 8 + i];
        }

        __des_decrypt_block(data_block, processed_block, key_sets);

        for (int i = 0; i < 8; i++)
        {
            dec_data[block_count * 8 + i] = processed_block[i];
        }
    }

    *dec_data_size = data_size;
    FREE(data_block);
    FREE(processed_block);
    FREE(key_sets);
}

// ===--- PERLIN NOISE ---======================================================
#define __PERLIN_NOISE

// ** uncomment if you want the repeatition on
// ** i.e. want to map the input point co-ordinates to their "local"
// ** co-ords
// int rep_amt = <REPEATITION_VALUE_HERE>
int __pn_rep_amt = -1;

// ✨ Permutation table to calculate the hashes for each corner
// of the unit cell. This contains ints from 0 to 255 inclusive.
int __PN_PERM_TABLE[256] = {0x97, 0xA0, 0x89, 0x5B, 0x5A, 0x0F, 0x83, 0x0D,
                            0xC9, 0x5F, 0x60, 0x35, 0xC2, 0xE9, 0x07, 0xE1,
                            0x8C, 0x24, 0x67, 0x1E, 0x45, 0x8E, 0x08, 0x63,
                            0x25, 0xF0, 0x15, 0x0A, 0x17, 0xBE, 0x06, 0x94,
                            0xF7, 0x78, 0xEA, 0x4B, 0x00, 0x1A, 0xC5, 0x3E,
                            0x5E, 0xFC, 0xDB, 0xCB, 0x75, 0x23, 0x0B, 0x20,
                            0x39, 0xB1, 0x21, 0x58, 0xED, 0x95, 0x38, 0x57,
                            0xAE, 0x14, 0x7D, 0x88, 0xAB, 0xA8, 0x44, 0xAF,
                            0x4A, 0xA5, 0x47, 0x86, 0x8B, 0x30, 0x1B, 0xA6,
                            0x4D, 0x92, 0x9E, 0xE7, 0x53, 0x6F, 0xE5, 0x7A,
                            0x3C, 0xD3, 0x85, 0xE6, 0xDC, 0x69, 0x5C, 0x29,
                            0x37, 0x2E, 0xF5, 0x28, 0xF4, 0x66, 0x8F, 0x36,
                            0x41, 0x19, 0x3F, 0xA1, 0x01, 0xD8, 0x50, 0x49,
                            0xD1, 0x4C, 0x84, 0xBB, 0xD0, 0x59, 0x12, 0xA9,
                            0xC8, 0xC4, 0x87, 0x82, 0x74, 0xBC, 0x9F, 0x56,
                            0xA4, 0x64, 0x6D, 0xC6, 0xAD, 0xBA, 0x03, 0x40,
                            0x34, 0xD9, 0xE2, 0xFA, 0x7C, 0x7B, 0x05, 0xCA,
                            0x26, 0x93, 0x76, 0x7E, 0xFF, 0x52, 0x55, 0xD4,
                            0xCF, 0xCE, 0x3B, 0xE3, 0x2F, 0x10, 0x3A, 0x11,
                            0xB6, 0xBD, 0x1C, 0x2A, 0xDF, 0xB7, 0xAA, 0xD5,
                            0x77, 0xF8, 0x98, 0x02, 0x2C, 0x9A, 0xA3, 0x46,
                            0xDD, 0x99, 0x65, 0x9B, 0xA7, 0x2B, 0xAC, 0x09,
                            0x81, 0x16, 0x27, 0xFD, 0x13, 0x62, 0x6C, 0x6E,
                            0x4F, 0x71, 0xE0, 0xE8, 0xB2, 0xB9, 0x70, 0x68,
                            0xDA, 0xF6, 0x61, 0xE4, 0xFB, 0x22, 0xF2, 0xC1,
                            0xEE, 0xD2, 0x90, 0x0C, 0xBF, 0xB3, 0xA2, 0xF1,
                            0x51, 0x33, 0x91, 0xEB, 0xF9, 0x0E, 0xEF, 0x6B,
                            0x31, 0xC0, 0xD6, 0x1F, 0xB5, 0xC7, 0x6A, 0x9D,
                            0xB8, 0x54, 0xCC, 0xB0, 0x73, 0x79, 0x32, 0x2D,
                            0x7F, 0x04, 0x96, 0xFE, 0x8A, 0xEC, 0xCD, 0x5D,
                            0xDE, 0x72, 0x43, 0x1D, 0x18, 0x48, 0xF3, 0x8D,
                            0x80, 0xC3, 0x4E, 0x42, 0xD7, 0x3D, 0x9C, 0xB4};

// Permutation table to calculate the hashes for each corner
int __pn_P[512];

// Flag to check if the permutation table exists
int __pn_perm_flag = 0;

/// @brief Initialize the permutation table with the default values
void pn_init_default()
{
    // double the permutation to avoid overflow
    for (int idx = 0; idx < 256; idx++)
    {
        __pn_P[256 + idx] = __pn_P[idx] = __PN_PERM_TABLE[idx];
    }
    // permtable created
    __pn_perm_flag = 1;
}

/// @brief Initialize the permutation table with random values
void pn_init_rand()
{
    // double the permutation to avoid overflow
    for (int idx = 0; idx < 256; idx++)
    {
        __pn_P[256 + idx] = __pn_P[idx] = rand() % 256;
    }
    // permtable created
    __pn_perm_flag = 1;
}

/// @brief Initialize the permutation table with the given values
/// @param perm_table The permutation table to initialize with,
/// must be of size 256
void pn_init(byte_t *perm_table)
{
    // double the permutation to avoid overflow
    for (int idx = 0; idx < 256; idx++)
    {
        __pn_P[256 + idx] = __pn_P[idx] = (int)perm_table[idx];
    }
    // permtable created
    __pn_perm_flag = 1;
}

/// @brief Linearly interpolate between the lo and hi values,
/// priority given by the param t
/// @param lo lower bound
/// @param hi upper bound
/// @param t priority value
/// @return float interpolated value
float __lerp(float lo, float hi, float t)
{
    return lo + t * (hi - lo);
}

/// @brief Calculate the dot product between the random chosen gradient vector
/// and the distance vector
/// @param hash The hash value to choose the gradient vector
/// @param x_comp x component of the distance vector
/// @param y_comp y component of the distance vector
/// @param z_comp z component of the distance vector
/// @return float dot product value
float __pn_grad(int hash, float x_comp, float y_comp, float z_comp)
{
    // use the first 4 bits of the hash to generate 12 random vectors
    // and "dot" them with (x_comp, y_comp, z_comp)

    int h = hash & 0xF;
    float w = h < 8 /* 0b1000 */
                  ? x_comp
                  : y_comp;

    float t = h < 4 /* 0b100 */
                  ? y_comp
                  : (h == 12 || h == 14
                         ? x_comp
                         : z_comp);

    // from the first two bits decide if w or t are positive or negative
    return ((h & 1) == 0 ? w : -w) + ((h & 2) == 0 ? t : -t);
}

/// @brief Fade function to smooth the interpolation, which has slope of zero
/// as it reaches the extremes 0 or 1. This is for the smoothness in the noise
/// value while interpolating
/// @param tf The input value to fade
/// @return float The faded value
float __pn_fadefunc(float tf)
{
    return tf * tf * tf * (tf * (6 * tf - 15) + 10);
}

/// @brief Increment the number and wrap around the repeatition amount
/// @param num The number to increment
/// @return int The incremented number
int __pn_rep_inc(int num)
{
    num++;
    num = __pn_rep_amt > 0 ? num % __pn_rep_amt : num;
    return num;
}

/// @brief Calculate the hashes of all the unit cell co-ords
/// @param xi The x co-ordinate of the unit cell
/// @param yi The y co-ordinate of the unit cell
/// @param zi The z co-ordinate of the unit cell
/// @return int* Stores the hashes into the hash_arr and returns a pointer
/// to the array
int *__pn_hash(int xi, int yi, int zi)
{
    int *hash_arr = ALLOC(int, 8);
    /*
      > There will be 8 hashes for each cell point.
        Here's the mapping:

        [0] : "aaa"
        [1] : "baa"
        [2] : "bba"
        [3] : "aba"
        [4] : "aab"
        [5] : "bab"
        [6] : "bbb"
        [7] : "abb"
    */
    hash_arr[0] /*aaa*/ = __pn_P[__pn_P[__pn_P[xi] + yi] + zi];
    hash_arr[1] /*baa*/ = __pn_P[__pn_P[__pn_P[__pn_rep_inc(xi)] + yi] + zi];
    hash_arr[2] /*bba*/ = __pn_P[__pn_P[__pn_P[__pn_rep_inc(xi)] +
                                        __pn_rep_inc(yi)] +
                                 zi];
    hash_arr[3] /*aba*/ = __pn_P[__pn_P[__pn_P[xi] + __pn_rep_inc(yi)] + zi];
    hash_arr[4] /*aab*/ = __pn_P[__pn_P[__pn_P[xi] + yi] + __pn_rep_inc(zi)];
    hash_arr[5] /*bab*/ = __pn_P[__pn_P[__pn_P[__pn_rep_inc(xi)] + yi] +
                                 __pn_rep_inc(zi)];
    hash_arr[6] /*bbb*/ = __pn_P[__pn_P[__pn_P[__pn_rep_inc(xi)] +
                                        __pn_rep_inc(yi)] +
                                 __pn_rep_inc(zi)];
    hash_arr[7] /*abb*/ = __pn_P[__pn_P[__pn_P[xi] + __pn_rep_inc(yi)] +
                                 __pn_rep_inc(zi)];

    return hash_arr;
}

/// @brief Generate the perlin noise value for the input co-ordinates
/// if repeat is on, make sure the input co-ordinate map to their "local"
/// co-ordinates i.e. make sure the co-ordinates wrap-around
/// @param inp_x The x co-ordinate of the input point
/// @param inp_y The y co-ordinate of the input point
/// @param inp_z The z co-ordinate of the input point
/// @return float The perlin noise value
float pn_noise(float inp_x, float inp_y, float inp_z)
{
    float x = inp_x;
    float y = inp_y;
    float z = inp_z;
    // the *i represent the co-ordinates of the unit cell in which
    // our input point is located.
    // the *f represent the relative co-ordinates of input point
    // relative to the unit cell i.e. (0.5, 0.5, 0.5) will be at the center
    // of the unit cell
    int xi, yi, zi;
    float xf, yf, zf;
    float u, v, w; // for fading the *f values

    if (__pn_rep_amt > 0)
    {
        x = remainderf(x, (float)__pn_rep_amt);
        y = remainderf(y, (float)__pn_rep_amt);
        z = remainderf(z, (float)__pn_rep_amt);
    }

    // init the *i and *f
    // the *i are bound to 255 to avoid overflow while creating the hashes i.e.
    // accessing the P[] array
    xi = (int)x & 255;
    yi = (int)y & 255;
    zi = (int)z & 255;

    xf = x - (int)x;
    yf = y - (int)y;
    zf = z - (int)z;

    // fade the *f for smoother interpolation
    u = __pn_fadefunc(xf);
    v = __pn_fadefunc(yf);
    w = __pn_fadefunc(zf);

    // get the hashes of all the unit cell co-ords
    int *hashes = __pn_hash(xi, yi, zi);

    // calculate the dot product between the gradient vectors
    // and the distance vectors and linearly interpolate between them
    // ...

    float x1 = __lerp(__pn_grad(hashes[0], xf, yf, zf),
                      __pn_grad(hashes[1], xf - 1, yf, zf), u);

    float x2 = __lerp(__pn_grad(hashes[3], xf, yf - 1, zf),
                      __pn_grad(hashes[2], xf - 1, yf - 1, zf), u);

    float y1 = __lerp(x1, x2, v); // 1

    // no need to redefine can overwrite the previously
    // "lerp-ed" values safely
    x1 = __lerp(__pn_grad(hashes[4], xf, yf, zf - 1),
                __pn_grad(hashes[5], xf - 1, yf, zf - 1), u);

    x2 = __lerp(__pn_grad(hashes[7], xf, yf - 1, zf - 1),
                __pn_grad(hashes[6], xf - 1, yf - 1, zf - 1), u);

    float y2 = __lerp(x1, x2, v); // 2

    FREE(hashes);

    // lerp the two y values and map em in the range [0, 1]
    return (__lerp(y1, y2, w) + 1) / 2;
}

/// @brief Generate more "noisy" noise using octaves
/// this is done by adding contributions of the noise function
/// iteratively and changing the amplitude and frequency of inputs
/// @param inp_x The x co-ordinate of the input point
/// @param inp_y The y co-ordinate of the input point
/// @param inp_z The z co-ordinate of the input point
/// @param octaves The number of octaves to generate
/// @return float The perlin noise value
float pn_octave_noise(float inp_x, float inp_y, float inp_z, int octaves)
{
    // The octave count and the persistance of each octave
    int octaveCount = octaves;
    float mulFreq = 2.f;
    float persistance = .5f;
    // "summed" noise, frequency and the max amplitude
    float noiseSum = 0.f;
    float currFreq = 1.f;
    float maxAmp = 0.f;
    float currAmp = 1.0f;

    // iterate through the octaves
    for (int i = 0; i < octaveCount; i++)
    {
        float currNoise = pn_noise(inp_x * currFreq,
                                   inp_y * currFreq,
                                   inp_z * currFreq) *
                          currAmp;
        noiseSum += currNoise;
        // resultant value will be in range [0, 1]
        maxAmp += currAmp;
        // increase the freq and decrease the amplitude
        currFreq *= mulFreq;
        currAmp *= persistance;
    }
    // map value in range [0, 1]
    return (noiseSum / maxAmp);
}

/// @brief Generate 1D perlin noise
/// @param data array to store the noise values
/// @param size size of the array
/// @param inc increment value
void pn_noise_1d(float *data, int size, float inc)
{
    float xoff = 0.f;
    for (int x = 0; x < size; x++)
    {
        data[x] = pn_noise(xoff, 0, 0);
        xoff += inc;
    }
}

/// @brief Generate 2D perlin noise
/// @param data array to store the noise values
/// @param rows
/// @param cols
/// @param inc increment value
void pn_noise_2d(float *data, int rows, int cols, float inc)
{
    // xoff and yoff for 2-D generation
    float xoff = 0.f, yoff = 0.f;

    for (int x = 0; x < rows; x++)
    {
        xoff += inc;
        yoff = 0; // for every xoff, yoff starts at zero
        for (int y = 0; y < cols; y++)
        {
            data[x * cols + y] = pn_noise(xoff, yoff, 0);
            yoff += inc;
        }
    }
}

/// @brief Generate 3D perlin noise
/// @param data array to store the noise values
/// @param rows
/// @param cols
/// @param depth
/// @param inc increment value
void pn_noise_3d(float *data, int rows, int cols, int depth, float inc)
{
    // xoff, yoff and zoff for 3-D generation
    float xoff = 0.f, yoff = 0.f, zoff = 0.f;

    for (int x = 0; x < rows; x++)
    {
        xoff += inc;
        yoff = 0; // for every xoff, yoff starts at zero
        for (int y = 0; y < cols; y++)
        {
            yoff += inc;
            zoff = 0; // for every yoff, zoff starts at zero
            for (int z = 0; z < depth; z++)
            {
                data[x * cols * depth + y * depth + z] =
                    pn_noise(xoff, yoff, zoff);
                zoff += inc;
            }
        }
    }
}

/// @brief Generate 1D perlin noise with octaves
/// @param data array to store the noise values
/// @param size
/// @param inc increment value
/// @param octaves number of octaves
void pn_octave_noise_1d(float *data, int size, float inc, int octaves)
{
    float xoff = 0.f;
    for (int x = 0; x < size; x++)
    {
        data[x] = pn_octave_noise(xoff, 0, 0, octaves);
        xoff += inc;
    }
}

/// @brief Generate 2D perlin noise with octaves
/// @param data array to store the noise values
/// @param rows
/// @param cols
/// @param inc increment value
/// @param octaves number of octaves
void pn_octave_noise_2d(float *data, int rows, int cols,
                        float inc, int octaves)
{
    // xoff and yoff for 2-D generation
    float xoff = 0.f, yoff = 0.f;

    for (int x = 0; x < rows; x++)
    {
        xoff += inc;
        yoff = 0; // for every xoff, yoff starts at zero
        for (int y = 0; y < cols; y++)
        {
            data[x * cols + y] = pn_octave_noise(xoff, yoff, 0, octaves);
            yoff += inc;
        }
    }
}

/// @brief Generate 3D perlin noise with octaves
/// @param data array to store the noise values
/// @param rows
/// @param cols
/// @param depth
/// @param inc increment value
/// @param octaves number of octaves
void pn_octave_noise_3d(float *data, int rows, int cols, int depth,
                        float inc, int octaves)
{
    // xoff, yoff and zoff for 3-D generation
    float xoff = 0.f, yoff = 0.f, zoff = 0.f;

    for (int x = 0; x < rows; x++)
    {
        xoff += inc;
        yoff = 0; // for every xoff, yoff starts at zero
        for (int y = 0; y < cols; y++)
        {
            yoff += inc;
            zoff = 0; // for every yoff, zoff starts at zero
            for (int z = 0; z < depth; z++)
            {
                data[x * cols * depth + y * depth + z] =
                    pn_octave_noise(xoff, yoff, zoff, octaves);
                zoff += inc;
            }
        }
    }
}

// ===--- BENCHMARKS ---========================================================
#define __BENCHMARKS

void rsa_bench()
{
    std::cout << "RSA BENCHMARK: ";
    auto bench_time = GET_CURR_TIME;
    uint_t epochs = 200;
    uint_t enc_epochs = 2000;
    uint_t p = 257; // 257
    uint_t q = 503; // 503

    MASSERT(is_prime(p) && is_prime(q), "p and q must be prime");
    uint_t _N = rsa_N(p, q);
    uint_t _t = rsa_t(p, q);
    auto time = GET_CURR_TIME;
    uint_t cif;
    for (uint_t i = 0; i < epochs; i++)
    {
        cif = rsa_public_key(_t);
    }

#ifdef TESTS_VERBOSE
    auto rsa_cif_t = GET_TIME_DIFF(time, GET_CURR_TIME);
#endif // TESTS_VERBOSE

    cif = _N / 2;
    while (!is_prime(cif))
    {
        cif++;
    }

    time = GET_CURR_TIME;
    uint_t dcif;
    for (uint_t i = 0; i < epochs; i++)
    {
        dcif = rsa_private_key(cif, _t);
    }

#ifdef TESTS_VERBOSE
    auto rsa_dcif_t = GET_TIME_DIFF(time, GET_CURR_TIME);
#endif // TESTS_VERBOSE

    uint_t num = 123;
    time = GET_CURR_TIME;
    uint_t encd;
    for (uint_t i = 0; i < enc_epochs; i++)
    {
        encd = rsa_encrypt(num, cif, _N);
    }

#ifdef TESTS_VERBOSE
    auto encd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
#endif // TESTS_VERBOSE

    time = GET_CURR_TIME;
    uint_t decd;
    for (uint_t i = 0; i < enc_epochs; i++)
    {
        decd = rsa_decrypt(encd, dcif, _N);
    }

#ifdef TESTS_VERBOSE
    auto decd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
    printf("\np\t\xB3");
    std::cout << p << std::endl;
    printf("q\t\xB3");
    std::cout << q << std::endl;
    printf("N\t\xB3");
    std::cout << _N << std::endl;
    printf("t\t\xB3");
    std::cout << _t << std::endl;
    printf("cif\t\xB3");
    std::cout << cif << std::endl;
    printf("c_key_t\t\xB3%.6fms\n",
           float(rsa_cif_t) / 1 / epochs);
    printf("dcif\t\xB3");
    std::cout << dcif << std::endl;
    printf("d_key_t\t\xB3%.6fms\n",
           float(rsa_dcif_t) / 1 / epochs);
    printf("sum_t\t\xB3%.6fms\n",
           float(rsa_dcif_t + rsa_cif_t) / 1 / epochs);
    printf("\nnum\t\xB3");
    std::cout << num << std::endl;
    printf("enc\t\xB3");
    std::cout << encd << std::endl;
    printf("enc_t\t\xB3%.6fms\n",
           float(encd_t) / 1 / enc_epochs);
    printf("dec\t\xB3");
    std::cout << decd << std::endl;
    printf("dec_t\t\xB3%.6fms\n",
           float(decd_t) / 1 / enc_epochs);
    printf("sum_t\t\xB3%.6fms\n",
           float(decd_t + encd_t) / 1 / enc_epochs);
#endif // TESTS_VERBOSE
    bool res = decd == num;
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(GET_TIME_DIFF(bench_time, GET_CURR_TIME)) / 1);
}

void elg_bench()
{
    std::cout << "ELG BENCHMARK: ";
    srand(time(0));
    uint_t p = 503;
    uint_t m = 20;
    MASSERT(is_prime(p), "p must be prime");
    MASSERT(m <= p, "m must be less than p");

    int pr_k_iter = 20;
    int pu_k_iter = 2000;
    int cif_iter = 20000;
    int dcif_iter = 20000;

    auto total_start = GET_CURR_TIME;
    uint_t key_x, key_y, key_g, a, b, decd;

#ifdef TESTS_VERBOSE
    auto time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_private_key(&key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_public_key(&key_y, &key_g, key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < cif_iter; i++)
    {
        elg_encrypt(&a, &b, m, key_y, key_g, p);
    }

#ifdef TESTS_VERBOSE
    auto cif_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < dcif_iter; i++)
    {
        decd = elg_decrypt(a, b, key_x, p);
    }

    auto total_t = GET_TIME_DIFF(total_start, GET_CURR_TIME);

#ifdef TESTS_VERBOSE
    auto decd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
    printf("\np\t\xB3");
    std::cout << p << std::endl;
    printf("m\t\xB3");
    std::cout << m << std::endl;
    printf("\nprivate key:\nx\t\xB3");
    std::cout << key_x << std::endl;
    printf("pr_k_t\t\xB3%.6fms\n",
           float(pr_k_time) / 1 / pr_k_iter);
    printf("\npublic key:\ny\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("pu_k_t\t\xB3%.6fms\n",
           float(pu_k_time) / 1 / pu_k_iter);
    printf("\ncif:\na\t\xB3");
    std::cout << a << std::endl;
    printf("b\t\xB3");
    std::cout << b << std::endl;
    printf("cif_t\t\xB3%.6fms\n",
           float(cif_time) / 1 / cif_iter);
    printf("\ndec:\t\xB3");
    std::cout << decd << std::endl;
    printf("dec_t\t\xB3%.6fms\n",
           float(decd_t) / 1 / dcif_iter);
#endif // TESTS_VERBOSE

    bool res = decd == m;
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(total_t) / 1);
}

void elgsig_bench()
{
    std::cout << "ELGSIG BENCHMARK: ";

    int pr_k_iter = 20;
    int pu_k_iter = 2000;
    int sig_iter = 20000;

    uint_t p = 503;
    uint_t m = 20;

    MASSERT(is_prime(p), "p must be prime");

    uint_t key_x, key_y, key_g, a, b;
    auto total_start = GET_CURR_TIME;
#ifdef TESTS_VERBOSE
    auto time = GET_CURR_TIME;
#endif // TESTS_VERBOSE
    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_private_key(&key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_public_key(&key_y, &key_g, key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < sig_iter; i++)
    {
        elgsig_sign(&a, &b, key_x, key_g, p, m);
    }
    auto total_t = GET_TIME_DIFF(total_start, GET_CURR_TIME);

#ifdef TESTS_VERBOSE
    auto sig_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    printf("\np\t\xB3");
    std::cout << p << std::endl;
    printf("m\t\xB3");
    std::cout << m << std::endl;
    printf("\nprivate key:\nx\t\xB3");
    std::cout << key_x << std::endl;
    printf("pr_k_t\t\xB3%.6fms\n",
           float(pr_k_time) / 1 / pr_k_iter);
    printf("\npublic key:\ny\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("pu_k_t\t\xB3%.6fms\n",
           float(pu_k_time) / 1 / pu_k_iter);
    printf("\nsig:\na\t\xB3");
    std::cout << a << std::endl;
    printf("b\t\xB3");
    std::cout << b << std::endl;
    printf("sig_t\t\xB3%.6fms\n",
           float(sig_time) / 1 / sig_iter);

#endif // TESTS_VERBOSE
    bool res = elgsig_check(key_y, key_g, a, b, p, m);
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(total_t) / 1);
}

// ===--- TESTS ---=============================================================
#define __TESTS

#ifndef TESTS_ENABLED

void test_rsa_array() {};
void test_elg_array() {};
void test_elgsig_array() {};

#else // TESTS_ENABLES

void test_rsa_array()
{
    uint_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    uint_t *cif = NULL;
    size_t cif_size;
    uint_t *dec = NULL;
    size_t dec_size;

    uint_t p = 13;
    uint_t q = 113;
    uint_t N = rsa_N(p, q);
    uint_t t = rsa_t(p, q);
    uint_t cif_key = rsa_public_key(t);
    uint_t dcif_key = rsa_private_key(cif_key, t);

    printf("TEST RSA ARRAY: ");
    rsa_encrypt(data, data_size, &cif, &cif_size, cif_key, N);
    rsa_decrypt(cif, cif_size, &dec, &dec_size, dcif_key, N);
    bool res = cmp_arrays(data, data_size, dec, dec_size);

#ifdef TESTS_VERBOSE
    printf("\nraw\t\xB3");
    print_array(data, data_size);
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("q\t\xB3");
    std::cout << q << std::endl;
    printf("N\t\xB3");
    std::cout << N << std::endl;
    printf("t\t\xB3");
    std::cout << t << std::endl;
    printf("c_key\t\xB3");
    std::cout << cif_key << std::endl;
    printf("d_key\t\xB3");
    std::cout << dcif_key << std::endl;
    printf("cif\t\xB3");
    print_array(cif, cif_size);
    printf("dcif\t\xB3");
    print_array(dec, dec_size);
#endif // TESTS_VERBOSE
    printf(res ? PASSED_STR : FAILED_STR);

    FREE(cif);
    FREE(dec);
}

void test_elg_array()
{
    uint_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    uint_t *cif = NULL;
    size_t cif_size;
    uint_t *dec = NULL;
    size_t dec_size;

    uint_t p = 503;

    uint_t key_x, key_y, key_g;

    elg_private_key(&key_x, p);
    elg_public_key(&key_y, &key_g, key_x, p);
    elg_encrypt(data, data_size, &cif, &cif_size, key_y, key_g, p);
    elg_dcif(cif, cif_size, &dec, &dec_size, key_x, p);
    bool res = cmp_arrays(data, data_size, dec, dec_size);

    printf("TEST ELG ARRAY: ");
#ifdef TESTS_VERBOSE
    printf("\nraw\t\xB3");
    print_array(data, data_size);
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("x\t\xB3");
    std::cout << key_x << std::endl;
    printf("y\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("cif\t\xB3");
    print_array(cif, cif_size);
    printf("dcif\t\xB3");
    print_array(dec, dec_size);
#endif // TESTS_VERBOSE
    printf(res ? PASSED_STR : FAILED_STR);

    FREE(cif);
    FREE(dec);
}

void test_elgsig_array()
{
    uint_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    uint_t *cif = NULL;
    size_t cif_size;

    uint_t p = 503;

    uint_t key_x, key_y, key_g;

    elg_private_key(&key_x, p);
    elg_public_key(&key_y, &key_g, key_x, p);
    elgsig_sign(data, data_size, &cif, &cif_size, key_x, key_g, p);
    bool res = elgsig_check(cif, cif_size, key_y, key_g, p, data, data_size);

    printf("TEST ELGSIG ARRAY: ");
#ifdef TESTS_VERBOSE
    printf("\nraw\t\xB3");
    print_array(data, data_size);
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("x\t\xB3");
    std::cout << key_x << std::endl;
    printf("y\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("cif\t\xB3");
    print_array(cif, cif_size);
#endif // TESTS_VERBOSE
    printf(res ? PASSED_STR : FAILED_STR);

    FREE(cif);
}

void test_des()
{
    // TODO: write DES test system
    byte_t *des_key_ = ALLOC(byte_t, 8);
    MASSERT(des_key_ != NULL, "Memory allocation error");

    des_key(des_key_);
    // 0x4530aa9d1a71e918
    des_key_[0] = 0x45;
    des_key_[1] = 0x30;
    des_key_[2] = 0xaa;
    des_key_[3] = 0x9d;
    des_key_[4] = 0x1a;
    des_key_[5] = 0x71;
    des_key_[6] = 0xe9;
    des_key_[7] = 0x18;

    printf("Key: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ", des_key_[i]);
    }
    printf("\n");
    byte_t data[] = {0x99, 0x97, 0x74, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    printf("Data: ");
    print_array_hex(data, data_size);

    // Encrypt
    byte_t *enc_data = ALLOC(byte_t, data_size);
    MASSERT(enc_data != NULL, "Memory allocation error");
    size_t enc_size;

    des_encrypt(data, data_size, enc_data, &enc_size, des_key_);

    printf("Encrypted data: ");
    print_array_hex(enc_data, enc_size);

    // Decrypt
    byte_t *dec_data = ALLOC(byte_t, data_size);
    MASSERT(dec_data != NULL, "Memory allocation error");
    size_t dec_size;

    des_decrypt(enc_data, enc_size, dec_data, &dec_size, des_key_);

    printf("Decrypted data: ");
    print_array_hex(dec_data, dec_size);

    FREE(des_key_);
}

#endif // TESTS_ENABLED

void test_perlin_noise()
{
    int rows = 1024;
    int cols = 1024;
    float *data = ALLOC(float, rows *cols);

    pn_init_rand();
    pn_octave_noise_2d(data, rows, cols, 0.01, 8);

    // print min max
    float min = data[0];
    float max = data[0];
    for (int i = 0; i < rows * cols; i++)
    {
        if (data[i] < min)
            min = data[i];
        if (data[i] > max)
            max = data[i];
    }
    printf("Min: %f, Max: %f\n", min, max);

    save_bmp_greyscale((float *)data, cols, rows,
                       (char *)"build/perlin_noise.bmp");

    FREE(data);
}

// ===--- INTERFACE ---=========================================================
#define __INTERFACE

void main_case_rsa_genkey()
{
    printf(RSA_STR);
    uint_t cif_key;
    uint_t dcif_key;
    printf("First prime number (p): ");
    uint_t p;
    std::cin >> p;
    if (p == 0)
    {
        while (!is_prime(p))
            p = rand() % 500 + 500;
        printf("Random prime number (p): %lld\n", (int64_t)p);
    }
    printf("Second prime number (q): ");
    uint_t q;
    std::cin >> q;
    if (q == 0)
    {
        while (!is_prime(q))
            q = rand() % 500 + 500;
        printf("Random prime number (q): %lld\n", (int64_t)q);
    }

    uint_t N = rsa_N(p, q);
    uint_t t = rsa_t(p, q);
    cif_key = rsa_public_key(t);
    dcif_key = rsa_private_key(cif_key, t);
    std::cout << "N (DEC): " << N << std::endl;
    std::cout << "t (DEC): " << t << std::endl;
    std::cout << "Public key (DEC): " << cif_key << std::endl;
    std::cout << "Private key (DEC): " << dcif_key << std::endl;
    getchar();
}

void main_case_rsa_encrypt()
{
    printf(RSA_STR);
    printf("Public key (DEC): ");
    uint_t cif_key;
    std::cin >> cif_key;
    printf("N (DEC): ");
    uint_t N;
    std::cin >> N;
    std::string input_str;
    std::cout << "Use shuffling? (y/n): ";
    char shuf;
    std::cin >> shuf;

    std::cout << "Enter sequence to encrypt:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        convert_str_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }

    uint_t *cif = NULL;
    size_t cif_size;
    rsa_encrypt(data, data_size, &cif, &cif_size, cif_key, N);

    if (shuf == 'y')
    {
        type_shuffle(cif, cif_size);
    }

    char *str_buf;
    // TODO: fix error when int is bigger than N
    swrite_dec_modulo(cif, cif_size, N, &str_buf);
    std::cout << C_CYAN "Encrypted sequence:" C_RESET " \n"
              << str_buf << std::endl;
    FREE(data);
    FREE(cif);
}

void main_case_rsa_decrypt()
{
    printf(RSA_STR);
    printf("Private key (DEC): ");
    uint_t prvt_key;
    std::cin >> prvt_key;
    printf("N (DEC): ");
    uint_t N;
    std::cin >> N;
    std::string input_str;
    std::cout << "Use shuffling? (y/n): ";
    char shuf;
    std::cin >> shuf;
    std::cout << "Enter sequence to decrypt:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    sread_dec_modulo((char *)input_str.c_str(), &data, &data_size, N);

    if (shuf == 'y')
    {
        type_unshuffle(data, data_size);
    }

    uint_t *dcif = NULL;
    size_t dcif_size;
    rsa_decrypt(data, data_size, &dcif, &dcif_size, prvt_key, N);
    std::cout << C_CYAN "Decrypted sequence (DEC):" C_RESET " \n";

    print_array(dcif, dcif_size);
    if (is_array_ascii(dcif, dcif_size))
    {
        char *str_buf = NULL;
        convert_array_to_str(dcif, dcif_size, &str_buf);
        std::cout << C_CYAN "Decrypted sequence (ASCII):" C_RESET " \n"
                  << str_buf << std::endl;
        FREE(str_buf);
    }
    FREE(data);
    FREE(dcif);
}

void main_case_elg_genkey()
{
    printf(ELGAMAL_STR);
    uint_t key_x, key_y, key_g;
    uint_t p;
    printf("N (DEC): ");
    std::cin >> p;
    if (p == 0)
    {
        while (!is_prime(p))
            p = rand() % 500 + 500;
        printf("Random N: %lld\n", (long long int)p);
    }
    elg_private_key(&key_x, p);
    elg_public_key(&key_y, &key_g, key_x, p);
    std::cout << "Private key (x, DEC): " << key_x << std::endl;
    std::cout << "Public key (y, DEC): " << key_y << std::endl;
    std::cout << "Generator (g, DEC): " << key_g << std::endl;
    getchar();
}

void main_case_elg_encrypt()
{
    printf(ELGAMAL_STR);
    printf("Public key (y, DEC): ");
    uint_t key_y;
    std::cin >> key_y;
    printf("Generator (g, DEC): ");
    uint_t key_g;
    std::cin >> key_g;
    printf("N (DEC): ");
    uint_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Use shuffling? (y/n): ";
    char shuf;
    std::cin >> shuf;
    std::cout << "Enter sequence to encrypt:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        convert_str_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    if (shuf == 'y')
    {
        type_shuffle(data, data_size);
    }
    uint_t *cif = NULL;
    size_t cif_size;
    elg_encrypt(data, data_size, &cif, &cif_size, key_y, key_g, p);
    char *str_buf = NULL;
    // TODO: fix error when int is bigger than N
    swrite_dec_modulo(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Encrypted sequence:" C_RESET " \n"
              << str_buf << std::endl;
    FREE(data);
    FREE(cif);
}

void main_case_elg_decrypt()
{
    printf(ELGAMAL_STR);
    printf("Private key (x, DEC): ");
    uint_t prvt_key;
    std::cin >> prvt_key;
    printf("N (DEC): ");
    uint_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Use shuffling? (y/n): ";
    char shuf;
    std::cin >> shuf;
    std::cout << "Enter sequence to decrypt:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    sread_dec_modulo((char *)input_str.c_str(), &data, &data_size, p);
    uint_t *dcif = NULL;
    size_t dcif_size;
    elg_dcif(data, data_size, &dcif, &dcif_size, prvt_key, p);
    if (shuf == 'y')
    {
        type_unshuffle(dcif, dcif_size);
    }
    std::cout << C_CYAN "Decrypted sequence (DEC):" C_RESET " \n";
    print_array(dcif, dcif_size);
    if (is_array_ascii(dcif, dcif_size))
    {
        char *str_buf = NULL;
        convert_array_to_str(dcif, dcif_size, &str_buf);
        std::cout << C_CYAN "Decrypted sequence (ASCII):" C_RESET " \n"
                  << str_buf << std::endl;
        FREE(str_buf);
    }
    FREE(data);
    FREE(dcif);
}

void main_case_elgsig_genkey()
{
    printf(ELGSIG_STR);
    uint_t key_x, key_y, key_g;
    uint_t p;
    printf("N (DEC): ");
    std::cin >> p;
    if (p == 0)
    {
        while (!is_prime(p))
            p = rand() % 500 + 500;
        printf("Random N: %lld\n", (int64_t)p);
    }
    elg_private_key(&key_x, p);
    elg_public_key(&key_y, &key_g, key_x, p);
    std::cout << "Private key (x, DEC): " << key_x << std::endl;
    std::cout << "Public key (y, DEC): " << key_y << std::endl;
    std::cout << "Generator (g, DEC): " << key_g << std::endl;
    getchar();
}

void main_case_elgsig_sign()
{
    printf(ELGSIG_STR);
    printf("Private key (x, DEC): ");
    uint_t key_x;
    std::cin >> key_x;
    printf("Generator (g, DEC): ");
    uint_t key_g;
    std::cin >> key_g;
    printf("N (DEC): ");
    uint_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to sign:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        convert_str_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    uint_t *cif = NULL;
    size_t cif_size;
    elgsig_sign(data, data_size, &cif, &cif_size, key_x, key_g, p);
    char *str_buf = NULL;
    swrite_dec_modulo(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Signature:" C_RESET "\n"
              << str_buf << std::endl;
    FREE(data);
    FREE(cif);
}

void main_case_elgsig_check()
{
    printf(ELGSIG_STR);
    printf("Public key (y, DEC): ");
    uint_t key_y;
    std::cin >> key_y;
    printf("Generator (g, DEC): ");
    uint_t key_g;
    std::cin >> key_g;
    printf("N (DEC): ");
    uint_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to check:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *data = NULL;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        convert_str_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    std::cout << "Enter signature:\n";
    std::getline(std::cin >> std::ws, input_str);
    uint_t *cif = NULL;
    size_t cif_size;
    sread_dec_modulo((char *)input_str.c_str(), &cif, &cif_size, p);
    // TODO: fix random errors (probably with overflow, appears with N > 0xFF)
    bool res = elgsig_check(cif, cif_size, key_y, key_g, p, data, data_size);
    std::cout << (res ? C_GREEN "Signature is valid" C_RESET " "
                      : C_RED "Signature is NOT valid" C_RESET " ")
              << std::endl;
    FREE(data);
    FREE(cif);
}

void main_case_des_genkey()
{
    printf(DES_STR);
    byte_t *des_key_ = ALLOC(byte_t, 8);
    des_key(des_key_);
    printf("Key: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02x", des_key_[i]);
    }
    printf("\n");
    getchar();
}

void main_case_des_encrypt()
{
    printf(DES_STR);
    printf("Key: ");
    std::string key_str;
    std::cin >> key_str;
    byte_t *key = NULL;
    size_t key_size;
    parse_hex_str(&key, &key_size, (char *)key_str.c_str());
    char shuf;
    std::cout << "Use shuffling? (y/n): ";
    std::cin >> shuf;
    printf("Enter sequence to encrypt:\n");
    std::string input_str;
    std::getline(std::cin >> std::ws, input_str);

    uint_t *data = NULL;
    size_t data_size;
    byte_t *bdata = NULL;
    size_t bdata_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        bdata = ALLOC(byte_t, input_str.size());
        memcpy(bdata, input_str.c_str(), input_str.size());
        bdata_size = input_str.size();
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
        to_byte_array(data, data_size, &bdata, &bdata_size);
    }
    padd_data_to_chunksize(&bdata, &bdata_size, 8);

    if (shuf == 'y')
    {
        type_shuffle(bdata, bdata_size);
    }

    size_t cif_size;
    byte_t *cif = ALLOC(byte_t, bdata_size);
    // TODO: remake decr func to accept pointer, not reference
    des_encrypt(bdata, bdata_size, cif, &cif_size, key);

    std::cout << C_CYAN "Encrypted sequence (HEX):" C_RESET " \n";
    print_array_hex_line(cif, cif_size);
    printf("\n");

    FREE(data);
    FREE(bdata);
    FREE(cif);
    FREE(key);
}

void main_case_des_decrypt()
{
    printf(DES_STR);
    printf("Key: ");
    std::string key_str;
    std::cin >> key_str;
    byte_t *key = NULL;
    size_t key_size;
    parse_hex_str(&key, &key_size, (char *)key_str.c_str());
    char shuf;
    std::cout << "Use shuffling? (y/n): ";
    std::cin >> shuf;
    printf("Enter sequence to decrypt (HEX):\n");
    std::string input_str;
    std::getline(std::cin >> std::ws, input_str);

    byte_t *data = NULL;
    size_t data_size;
    parse_hex_str(&data, &data_size, (char *)input_str.c_str());

    size_t dec_size = data_size;
    byte_t *dec = ALLOC(byte_t, dec_size);
    MASSERT(dec != NULL, "Memory allocation error");
    // TODO: rewrite decr func to accept pointer, not reference
    des_decrypt(data, data_size, dec, &dec_size, key);

    if (shuf == 'y')
    {
        type_unshuffle(dec, dec_size);
    }

    std::cout << C_CYAN "Decrypted sequence (HEX):" C_RESET " \n";
    print_array_hex_line(dec, dec_size);
    printf("\n");
    std::cout << C_CYAN "Decrypted sequence (ASCII):" C_RESET " \n";
    print_array_ascii((char *)dec, dec_size);
    printf("\n");
    FREE(data);
    FREE(dec);
    FREE(key);
}

void main_interface()
{
    while (1)
    {
        ime_enter_alt_screen();
        // ime_exit_alt_screen();
        ime_clear_screen();

        printf(IME_ESC IME_RGB_COLOR(0, 255, 255) IME_ESC_END
               "CIFS.CPP" C_RESET " \n");
        printf("===--- CIFS \n");
        printf("  1) RSA\n");
        printf("  2) ElGamal\n");
        printf("  3) ElGamal Signature\n");
        printf("  4) DES\n");
        // printf("===--- BENCHMARKS \n");
        // printf("  4) RSA\n");
        // printf("  5) ElGamal\n");
        // printf("  6) ElGamal Signature\n");
        // printf("  7) Run all tests\n");

#define __ML_RSA 1
#define __ML_ELGAMAL 2
#define __ML_ELGAMAL_SIG 3
#define __ML_DES 4
#define __ML_RSA_BENCH 5
#define __ML_ELGAMAL_BENCH 6
#define __ML_ELGAMAL_SIG_BENCH 7
#define __ML_TESTS 8

        printf(INPUT_STR);
        int input;
        std::cin >> input;
        ime_clear_screen();

        switch (input)
        {
        case __ML_RSA:
        {
            printf(RSA_STR);
            printf("===--- MODES \n");
            printf("  1) Generate keys\n");
            printf("  2) Encrypt\n");
            printf("  3) Decrypt\n");

            printf(INPUT_STR);
            std::cin >> input;
            ime_clear_screen();

            switch (input)
            {
            case 1:
            {
                main_case_rsa_genkey();
                break;
            }
            case 2:
            {
                main_case_rsa_encrypt();
                break;
            }
            case 3:
            {
                main_case_rsa_decrypt();
                break;
            }
            default:
            {
                printf(INVALID_INPUT_STR);
                getchar();
                return;
            }
            }
            break;
        }
        case __ML_ELGAMAL:
        {
            printf(ELGAMAL_STR);
            printf("===--- MODES \n");
            printf("  1) Generate keys\n");
            printf("  2) Encrypt\n");
            printf("  3) Decrypt\n");

            printf(INPUT_STR);
            std::cin >> input;
            ime_clear_screen();

            switch (input)
            {
            case 1:
            {
                main_case_elg_genkey();
                break;
            }
            case 2:
            {
                main_case_elg_encrypt();
                break;
            }
            case 3:
            {
                main_case_elg_decrypt();
                break;
            }
            default:
            {
                printf(INVALID_INPUT_STR);
                return;
            }
            }
            break;
        }
        case __ML_ELGAMAL_SIG:
        {
            printf(ELGSIG_STR);
            printf("===--- MODES \n");
            printf("  1) Generate keys\n");
            printf("  2) Sign\n");
            printf("  3) Check sign\n");

            printf(INPUT_STR);
            std::cin >> input;
            ime_clear_screen();

            switch (input)
            {
            case 1:
            {
                main_case_elgsig_genkey();
                break;
            }
            case 2:
            {
                main_case_elgsig_sign();
                break;
            }
            case 3:
            {
                main_case_elgsig_check();
                break;
            }
            default:
            {
                printf(INVALID_INPUT_STR);
                getchar();
                return;
            }
            }
            break;
        }
        case __ML_DES:
        {
            printf(DES_STR);
            printf("===--- MODES \n");
            printf("  1) Generate keys\n");
            printf("  2) Encrypt\n");
            printf("  3) Decrypt\n");

            printf(INPUT_STR);
            std::cin >> input;
            ime_clear_screen();

            switch (input)
            {
            case 1:
            {
                main_case_des_genkey();
                break;
            }
            case 2:
            {
                main_case_des_encrypt();
                break;
            }
            case 3:
            {
                main_case_des_decrypt();
                break;
            }
            default:
            {
                printf(INVALID_INPUT_STR);
                return;
            }
            }
            break;
        }
        case __ML_RSA_BENCH:
        {
            ime_exit_alt_screen();
            rsa_bench();
            getchar();
            break;
        }
        case __ML_ELGAMAL_BENCH:
        {
            ime_exit_alt_screen();
            elg_bench();
            getchar();
            break;
        }
        case __ML_ELGAMAL_SIG_BENCH:
        {
            ime_exit_alt_screen();
            elgsig_bench();
            getchar();
            break;
        }
        case __ML_TESTS:
        {
            ime_exit_alt_screen();
            printf(TESTS_STR);
            test_rsa_array();
            test_elg_array();
            test_elgsig_array();
            test_des();
            rsa_bench();
            elg_bench();
            elgsig_bench();
            getchar();
            break;
        }
        default:
        {
            ime_exit_alt_screen();
            printf(INVALID_INPUT_STR);
            return;
        }
        }

        getchar();
        ime_exit_alt_screen();
    }
}

// ===--- <DEV> ---=============================================================

/// @brief Rotate array to the left on n bytes.
/// @param data
/// @param size
/// @param n
void rol_byte_array(byte_t *data, size_t size, size_t n)
{
    byte_t *tmp = ALLOC(byte_t, size);
    MASSERT(tmp != NULL, "Memory allocation error");
    memcpy(tmp, data, size);
    for (size_t i = 0; i < size; i++)
    {
        data[i] = tmp[(i + n) % size];
    }
    FREE(tmp);
}

/// @brief Rotate array to the left on n bits.
/// @param data
/// @param size
/// @param n
void rol_bit_array(byte_t *data, size_t size, size_t n)
{
    n = n % (size * 8); // Ensure n is within the bit size of the array
    if (n == 0)
        return; // If no rotation is needed, return

    bool carry1 = false;
    bool carry2 = false;
    for (size_t i = 0; i < n; i++)
    {
        for (size_t j = 0; j < size; j++)
        {
            carry1 = data[j] & 0b10000000;
            data[j] <<= 1;
            if (carry2)
                data[j] |= 0x01;
            carry2 = carry1;
        }
        if (carry2)
            data[size - 1] |= 0x01;
        carry1 = false;
        carry2 = false;
    }
}

/// @brief Rotate array to the right on n bytes.
/// @param data
/// @param size
/// @param n
void ror_byte_array(byte_t *data, size_t size, size_t n)
{
    byte_t *tmp = ALLOC(byte_t, size);
    MASSERT(tmp != NULL, "Memory allocation error");
    memcpy(tmp, data, size);
    for (size_t i = 0; i < size; i++)
    {
        data[i] = tmp[(i - n + size) % size];
    }
    FREE(tmp);
}

/// @brief Rotate full array to the right on n bits.
/// ror on 3 = 0b1010111000101010 -> 0b0101010111000101
/// @param data
/// @param size
/// @param n
void ror_bit_array(byte_t *data, size_t size, size_t n)
{
    n = n % (size * 8); // Ensure n is within the bit size of the array
    if (n == 0)
        return; // If no rotation is needed, return

    bool carry1 = false;
    bool carry2 = false;
    for (size_t i = 0; i < n; i++)
    {
        for (size_t j = 0; j < size; j++)
        {
            carry1 = data[j] & 0x01;
            data[j] >>= 1;
            if (carry2)
                data[j] |= 0b10000000;
            carry2 = carry1;
        }
        if (carry2)
            data[0] |= 0b10000000;
        carry1 = false;
        carry2 = false;
    }
}

/// @brief Resize key in a smart way.
/// If key is bigger than new_key_size, it will be ror'd on n's byte and then
/// cutted. If key is smaller than new_key_size, it will be filled with ror'd
/// on n's byte key.
/// @param input_key
/// @param input_key_size
/// @param new_key
/// @param new_key_size
void resize_key(byte_t *input_key, size_t input_key_size,
                byte_t *new_key, size_t new_key_size)
{
    byte_t *input_copy = ALLOC(byte_t, input_key_size);
    MASSERT(input_copy != NULL, "Memory allocation error");
    memcpy(input_copy, input_key, input_key_size);

    if (input_key_size == new_key_size)
    {
        memcpy(new_key, input_copy, new_key_size);
    }
    else if (input_key_size > new_key_size)
    {
        size_t n = input_copy[0] % input_key_size;
        ror_bit_array(input_copy, input_key_size, n);
        memcpy(new_key, input_copy, new_key_size);
    }
    else
    {
        // for every full input key repetition, ror it on i's byte of input key
        // TODO: look in this *wires* and probably fix it (may be writing
        // over other memory part)
        std::cout << (new_key_size + input_key_size - 1) /
                         input_key_size
                  << std::endl;

        for (size_t i = 0; i < (new_key_size + input_key_size - 1) /
                                   input_key_size;
             i++)
        {
            size_t n = (input_key[i % input_key_size] % 6) + 1;
            ror_bit_array(input_copy, input_key_size, n);
            std::cout << i << ": n: " << n << " - ";
            print_array_hex_line(input_copy, input_key_size);
            printf("\n");
            memcpy(new_key + i * input_key_size, input_copy, input_key_size);
        }
    }
    FREE(input_copy);
}

/// @brief Calculate size of 2D array's diagonal line.
/// @param rows
/// @param cols
/// @return size_t Diagonal line size
size_t calc_diag_line_size(size_t rows, size_t cols)
{
    return rows < cols ? rows : cols;
}

/// @brief Get diagonal line from 2D array.
/// @param data
/// @param rows
/// @param cols
/// @param line
/// @param line_size
void get_diag_line(float *data, size_t rows, size_t cols,
                   float *line, size_t line_size)
{
    for (size_t i = 0; i < line_size; i++)
    {
        line[i] = data[i * cols + i];
    }
}

void get_alt_diag_line(float *data, size_t rows, size_t cols,
                       float *line, size_t line_size)
{
    for (size_t i = 0; i < line_size; i++)
    {
        line[i] = data[i * cols + line_size - i - 1];
    }
}

void get_comb_diag_line(float *data, size_t rows, size_t cols,
                        float *line, size_t line_size)
{
    for (size_t i = 0; i < line_size; i++)
    {
        line[i] = data[i * cols + i];
        line[i] += data[i * cols + line_size - i - 1];
    }

    for (size_t i = 0; i < line_size; i++)
    {
        line[i] /= 2;
    }
}

/// @brief Get horizontal line from 2D array.
/// @param data
/// @param rows
/// @param cols
/// @param line
/// @param line_size
/// @param line_num Number of line to get
void get_hor_line(float *data, size_t rows, size_t cols,
                  float *line, size_t line_size, size_t line_num)
{
    memcpy(line, data + line_num * cols, line_size * sizeof(float));
}

/// @brief Get vertical line from 2D array.
/// @param data
/// @param rows
/// @param cols
/// @param line
/// @param line_size
/// @param line_num Number of line to get
void get_vert_line(float *data, size_t rows, size_t cols,
                   float *line, size_t line_size, size_t line_num)
{
    for (size_t i = 0; i < line_size; i++)
    {
        line[i] = data[i * cols + line_num];
    }
}

void get_spiral_line(float *data, size_t rows, size_t cols,
                     float *line, size_t line_size)
{
    size_t top = 0, bottom = rows - 1, left = 0, right = cols - 1;
    size_t index = 0;

    while (top <= bottom && left <= right && index < line_size)
    {
        for (size_t i = left; i <= right && index < line_size; ++i)
        {
            line[index++] = data[top * cols + i];
        }
        ++top;

        for (size_t i = top; i <= bottom && index < line_size; ++i)
        {
            line[index++] = data[i * cols + right];
        }
        --right;

        if (top <= bottom)
        {
            for (size_t i = right; i >= left && index < line_size; --i)
            {
                line[index++] = data[bottom * cols + i];
            }
            --bottom;
        }

        if (left <= right)
        {
            for (size_t i = bottom; i >= top && index < line_size; --i)
            {
                line[index++] = data[i * cols + left];
            }
            ++left;
        }
    }
}

/// @brief Normalize array to [0, 1] range.
/// @param data
/// @param size
void normalize_array(float *data, size_t size)
{
    float min = data[0];
    float max = data[0];
    for (size_t i = 0; i < size; i++)
    {
        if (data[i] < min)
            min = data[i];
        if (data[i] > max)
            max = data[i];
    }
    for (size_t i = 0; i < size; i++)
    {
        data[i] = (data[i] - min) / (max - min);
    }
}

/// @brief Debug function
void dev_func()
{
    byte_t des_key[8] = {0xb1, 0x18, 0x81, 0x38, 0xa0, 0xd7, 0xe4, 0x5f};

    size_t pn_key_size = 256;
    byte_t *pn_key = ALLOC(byte_t, pn_key_size);
    MASSERT(pn_key != NULL, "Memory allocation error");

    print_array_hex(des_key, 8);
    print_array_hex_line(des_key, 8);
    printf("\n");
    resize_key(des_key, 8, pn_key, pn_key_size);
    print_array_hex(pn_key, pn_key_size);

    pn_init(pn_key);

    int rows = 64;
    int cols = 64;
    float *data = ALLOC(float, rows *cols);
    MASSERT(data != NULL, "Memory allocation error");

    pn_octave_noise_2d(data, rows, cols, 0.3, 2);
    normalize_array(data, rows * cols);

    size_t diag_size = calc_diag_line_size(rows, cols);
    float *diag = ALLOC(float, diag_size);
    size_t hor_size = cols;
    float *hor = ALLOC(float, hor_size);
    size_t vert_size = rows;
    float *vert = ALLOC(float, vert_size);
    size_t spiral_size = calc_diag_line_size(rows, cols);
    float *spiral = ALLOC(float, spiral_size);

    get_comb_diag_line(data, rows, cols, diag, diag_size);
    normalize_array(diag, diag_size);
    print_array_fmt(diag, diag_size, (char *)"%.2f");

    get_hor_line(data, rows, cols, hor, hor_size, 0);
    normalize_array(hor, hor_size);
    print_array_fmt(hor, hor_size, (char *)"%.2f");

    get_vert_line(data, rows, cols, vert, vert_size, 0);
    normalize_array(vert, vert_size);
    print_array_fmt(vert, vert_size, (char *)"%.2f");

    get_spiral_line(data, rows, cols, spiral, spiral_size);
    normalize_array(spiral, spiral_size);
    print_array_fmt(spiral, spiral_size, (char *)"%.2f");

    save_bmp_greyscale((float *)data, cols, rows,
                       (char *)"build/perlin_noise.bmp");

    FREE(data);
    FREE(pn_key);
}

// ===--- </DEV> ---============================================================

static const char *const usages[] = {
    "cifs [options] [[--] args]",
    "cifs [options]",
    "cifs",
    NULL,
};

int main(int argc, const char **argv)
{
    // Main random seed
    srand(std::chrono::system_clock::now().time_since_epoch().count());

    // Argumets parsing
    if (argc != 1)
    {
        int fix_screen = 0;
        int dev = 0;
        const char *ring = NULL;
        const char *file = NULL;
        const char *key = NULL;
        const char *add_key = NULL;
        const char *output = NULL;
        const char *mode = NULL;
        int encrypt = 0;
        int decrypt = 0;
        struct argparse_option options[] = {
            OPT_HELP(),

            OPT_GROUP(C_HEADER "Basic options" C_RESET " "),
            OPT_BOOLEAN('V', "verbose", &log_verbose_lvl,
                        "log all processes", NULL, 0, 0),
            OPT_BOOLEAN('Q', "quiet", &log_quiet_lvl,
                        "log only errors", NULL, 0, 0),
            OPT_BOOLEAN((char)NULL, "shutup", &log_shutup_lvl,
                        "log nothing", NULL, 0, 0),
            OPT_STRING('m', "mode", &mode,
                       "mode to run",
                       NULL, 0, 0),

            OPT_GROUP(C_HEADER "RSA" C_RESET " <rsa>"),
            OPT_BOOLEAN('e', "encrypt", &encrypt, "encrypt data", NULL, 0, 0),
            OPT_BOOLEAN('d', "decrypt", &decrypt, "decrypt data", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "output", &output,
                       "path to output file", NULL, 0, 0),
            OPT_STRING('k', "key", &key, "encrypting/decrypting key", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),
            OPT_BOOLEAN('s', "shuffle", &shuffle, "shuffle data", NULL, 0, 0),

            OPT_GROUP(C_HEADER "ElGamal" C_RESET " <elg>"),
            OPT_BOOLEAN('e', "encrypt", &encrypt, "encrypt data", NULL, 0, 0),
            OPT_BOOLEAN('d', "decrypt", &decrypt, "decrypt data", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "output", &output,
                       "path to output file", NULL, 0, 0),
            OPT_STRING('k', "key", &key,
                       "encrypting / decrypting key", NULL, 0, 0),
            OPT_STRING('g', "generator", &add_key,
                       "generator key (encrypting)", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),
            OPT_BOOLEAN('s', "shuffle", &shuffle, "shuffle data", NULL, 0, 0),

            OPT_GROUP(C_HEADER "ElGamal signature" C_RESET " <elgsig>"),
            OPT_BOOLEAN('s', "sign", &encrypt, "sign data", NULL, 0, 0),
            OPT_BOOLEAN('c', "check", &decrypt, "check sign", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "signature", &output,
                       "path to output file / signature", NULL, 0, 0),
            OPT_STRING('k', "key", &key, "signing / checking key", NULL, 0, 0),
            OPT_STRING('g', "generator", &add_key,
                       "generator key (signing)", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),
            OPT_BOOLEAN('s', "shuffle", &shuffle, "shuffle data", NULL, 0, 0),

            OPT_GROUP(C_HEADER "DES" C_RESET " <des>"),

            OPT_GROUP(C_HEADER "Maintenance options" C_RESET " "),
            OPT_BOOLEAN((char)NULL, "fix-screen", &fix_screen,
                        "exit alt screen, use it when scroll bar disappears",
                        NULL, 0, 0),
            OPT_BOOLEAN((char)NULL, "dev", &dev,
                        "dev mode",
                        NULL, 0, 0),
            OPT_END(),
        };

        struct argparse argparse;
        argparse_init(&argparse, options, usages, 0);
        argparse_describe(&argparse, "\nTMP opening msg", "\nFor more info go to Git repo: https://github.com/Kseen715/cifs.cpp");
        argc = argparse_parse(&argparse, argc, argv);
        if (fix_screen != 0)
        {
            ime_exit_alt_screen();
            return 0;
        }

        // If nothing is set, set default logging level
        if (log_verbose_lvl) // If 1 -> extended logging
        {
            log_verbose_lvl = 1;
            log_common_lvl = 1;
            log_quiet_lvl = 1;
            log_shutup_lvl = 1;
        }
        if (log_quiet_lvl) // If 1 -> quiet logging, only errors
        {
            log_verbose_lvl = 0;
            log_common_lvl = 0;
            log_quiet_lvl = 1;
            log_shutup_lvl = 1;
        }
        if (log_shutup_lvl) // If 1 -> no logging
        {
            log_verbose_lvl = 0;
            log_common_lvl = 0;
            log_quiet_lvl = 0;
            log_shutup_lvl = 1;
        }

        if (dev)
        {
            dev_func();
            return 0;
        }

        size_t chunk_size = 1024 * 1024; // 1MB
        size_t chunk_count;

        // Common data arrays.
        byte_t *data = NULL;
        size_t data_size;

        uint_t *data_int = NULL;
        size_t data_int_size;

        uint_t *cif = NULL;
        size_t cif_size;

        byte_t *dcif = NULL;
        size_t dcif_size;

        byte_t *bytes = NULL;
        size_t bytes_size;

        if (is_str_eq("rsa", mode))
        {
            if (encrypt)
            {
                if (log_verbose_lvl)
                    printf("RSA encrypte\n");
                MASSERT(file != NULL, "File path is required");
                MASSERT(ring != NULL, "N key is required");
                MASSERT(key != NULL, "Key is required");
                if (output == NULL)
                {
                    output = ALLOC(char, strlen(file) + 6);
                    strcpy((char *)output, file);
                    strcat((char *)output, ".ciph");
                }

                chunk_size = (file_size(file) / 100) + 1;
                chunk_count = count_file_chunks(file, chunk_size);

                auto iter = tq::tqdm(tq::range((size_t)0, chunk_count));
                iter.set_prefix("RSA encrypting: ");

                if (log_quiet_lvl)
                    iter.set_ostream(devnull);
                if (log_common_lvl)
                    std::cout << "Chunk size: "
                              << chunk_size << " bytes" << std::endl;
                for (auto i : iter)
                {
                    read_bin_file_chunk(&data, &data_size,
                                        i * chunk_size,
                                        (i + 1) * chunk_size, file);
                    if (log_verbose_lvl)
                    {
                        printf("Data: ");
                        print_array_hex(data, data_size);
                    }

                    rsa_encrypt(data, data_size,
                                &cif, &cif_size,
                                atoi(key), atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Encrypted: ");
                        print_array_hex(cif, cif_size);
                    }

                    convert_array_to_bytes_modulo(cif, cif_size,
                                                  &bytes, &bytes_size,
                                                  atoi(ring));
                    write_bin_file_chunk(
                        bytes,
                        bytes_size,
                        i * chunk_size * ((hex_num_len(atoi(ring)) + 1) / 2),
                        output);
                    if (log_verbose_lvl)
                    {
                        printf("Written: ");
                        print_array_hex(bytes, bytes_size);
                    }
                    FREE(data);
                    FREE(cif);
                    FREE(bytes);
                }
                std::cout << std::endl;
            }
            else if (decrypt)
            {
                MASSERT(file != NULL, "File path is required");
                MASSERT(ring != NULL, "N key is required");
                MASSERT(key != NULL, "Key is required");
                if (file != NULL && strlen(file) > 5)
                {
                    if (strcmp(file + strlen(file) - 5, ".ciph") != 0)
                    {
                        printf(C_RED "File is not a .ciph file" C_RESET " \n");
                        return 0;
                    }
                }
                if (output == NULL)
                {
                    output = ALLOC(char, strlen(file) - 5);
                    strncpy((char *)output, file, strlen(file) - 5);
                    ((char *)output)[strlen(file) - 5] = '\0';
                }

                chunk_size = (file_size(file) / 100) + 1;
                chunk_count = count_file_chunks(file, chunk_size);

                auto iter = tq::tqdm(tq::range((size_t)0, chunk_count));
                iter.set_prefix("RSA decrypting: ");

                if (log_quiet_lvl)
                    iter.set_ostream(devnull);
                if (log_common_lvl)
                    std::cout << "Chunk size: "
                              << chunk_size << " bytes" << std::endl;
                for (auto i : iter)
                {
                    read_bin_file_chunk(&data,
                                        &data_size,
                                        i * chunk_size,
                                        (i + 1) * chunk_size,
                                        file);
                    if (log_verbose_lvl)
                    {
                        printf("Data: ");
                        print_array_hex(data, data_size);
                    }

                    convert_bytes_to_array_modulo<uint_t>(data,
                                                          data_size,
                                                          &data_int,
                                                          &data_int_size,
                                                          atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Data int: ");
                        print_array(data_int, data_int_size);
                    }

                    rsa_decrypt(data_int,
                                data_int_size,
                                &dcif,
                                &dcif_size,
                                atoi(key),
                                atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Decrypted: ");
                        print_array_hex(dcif, dcif_size);
                    }

                    write_bin_file_chunk(
                        dcif,
                        dcif_size,
                        i * chunk_size / ((hex_num_len(atoi(ring)) + 1) / 2),
                        output);
                    if (log_verbose_lvl)
                    {
                        printf("Written: ");
                        print_array_hex(dcif, dcif_size);
                    }
                    FREE(data);
                    FREE(data_int);
                    FREE(dcif);
                }
                free((void *)output);
            }
            else
            {
                printf(C_RED "Provide RSA mode '-e' or '-d'" C_RESET " \n");
                return 0;
            }
        }
        else if (is_str_eq("elg", mode))
        {
            printf("ElGamal\n");
        }
        else if (is_str_eq("elgsig", mode))
        {
            printf("ElGamal signature\n");
        }
        else
        {
            printf(C_RED "Invalid mode" C_RESET " \n");
            return 0;
        }

        if (argc != 0)
        {
            printf("argc: %d\n", argc);
            int i;
            for (i = 0; i < argc; i++)
            {
                printf("argv[%d]: %s\n", i, *(argv + i));
            }
        }

        return 0;
    }
    main_interface();
    return 0;
}