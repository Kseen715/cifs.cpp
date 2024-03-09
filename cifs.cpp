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

// Time measurement
#define GET_CURR_TIME std::chrono::system_clock::now()
#define GET_TIME_DIFF(start, end) \
    std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()

// Preferrable allocators
#define ALLOC(T, size) ((T *)malloc((size) * sizeof(T)))
#define CALLOC(T, size) ((T *)calloc((size), sizeof(T)))
#define REALLOC(T, ptr, size) ((T *)realloc(ptr, (size) * sizeof(T)))

// Common integer type (signed)
#define int_t int

// Common byte type
#define byte_t uint8_t

// Copies vector's data to array
#define SCRAP_VECTOR(dst, vec, T) \
    dst = ALLOC(T, (vec).size()); \
    memcpy(dst, (vec).data(), (vec).size() * sizeof(T))

// Colors
#define C_RESET IME_ESC IME_RESET IME_ESC_END
#define C_RED IME_ESC IME_RED IME_ESC_END
#define C_GREEN IME_ESC IME_GREEN IME_ESC_END
#define C_CYAN IME_ESC IME_RGB_COLOR(0, 200, 180) IME_ESC_END
#define C_DIMM IME_ESC IME_BRIGHT_BLACK IME_ESC_END
#define C_HEADER IME_ESC IME_RGB_COLOR(255, 117, 24) IME_ESC_END

// Strings
#define TESTS_STR IME_ESC IME_RGB_COLOR(255, 255, 100) IME_ESC_END \
    "TESTS:" C_RESET "\n"
#define INPUT_STR "\n" C_DIMM "Input:" C_RESET " "
#define INVALID_INPUT_STR \
    C_RED                 \
    "Invalid input" C_RESET "\n"
#define RSA_STR IME_ESC IME_RGB_COLOR(100, 100, 255) IME_ESC_END \
    "RSA:" C_RESET "\n"
#define ELGAMAL_STR IME_ESC IME_RGB_COLOR(100, 255, 100) IME_ESC_END \
    "ElGamal:" C_RESET "\n"
#define ELGSIG_STR IME_ESC IME_RGB_COLOR(255, 85, 0) IME_ESC_END \
    "ElGamal Signature:" C_RESET "\n"

#ifdef TESTS_VERBOSE
#define PASSED_STR IME_ESC IME_GREEN IME_ESC_END \
    "===--> PASSED\n\n" C_RESET
#define PASSED_TIME_FMT IME_ESC IME_GREEN IME_ESC_END \
    "===--> PASSED: %.6fms\n\n" C_RESET
#define FAILED_STR IME_ESC IME_RED IME_ESC_END \
    "===--> FAILED\n\n" C_RESET
#else
#define PASSED_STR IME_ESC IME_GREEN IME_ESC_END \
    "PASSED\n" C_RESET
#define PASSED_TIME_FMT IME_ESC IME_GREEN IME_ESC_END \
    "PASSED: %.6fms\n" C_RESET
#define FAILED_STR IME_ESC IME_RED IME_ESC_END \
    "FAILED\n" C_RESET
#endif // TESTS_VERBOSE

#ifdef _WIN32
std::ofstream devnull("NUL");
#else
std::ofstream devnull("/dev/null");
#endif

// ===--- ESSENTIALS ---========================================================
#define __ESSENTIALS

bool is_prime(int_t x)
{
    if (x < 2)
    {
        return false;
    }
    for (int_t i = 2; i * i <= x; i++)
    {
        if (x % i == 0)
        {
            return false;
        }
    }
    return true;
}

int_t pow_int(int_t x, int_t pow)
{
    int_t res = 1;
    for (int_t i = 0; i < pow; i++)
    {
        res *= x;
    }
    return res;
}

int_t pow_mod(int_t x, int_t pow, int_t mod)
{
    int_t res = 1;
    for (int_t i = 0; i < pow; i++)
    {
        res = (res * x) % mod;
    }
    return res;
}

byte_t pow_mod(byte_t x, int_t pow, int_t mod)
{
    byte_t res = 1;
    for (int_t i = 0; i < pow; i++)
    {
        res = (res * x) % mod;
    }
    return res;
}

bool is_primitive_root_mod(int_t g, int_t p)
{
    for (int_t j = 1; j < p - 1; j++)
    {
        if (pow_mod(g, j, p) == 1)
        {
            return false;
        }
    }
    return true;
}

int_t primitive_root_mod(int_t p)
{
    for (int_t i = 2; i < p; i++)
    {
        if (is_primitive_root_mod(i, p))
        {
            return i;
        }
    }
    return -1;
}

int_t coprime(int_t num)
{
    for (int_t i = 2; i < num; i++)
    {
        if (num % i != 0)
        {
            return i;
        }
    }
    return -1;
}

int_t get_multiplicative_inverse(int_t k, int_t p)
{
    for (int_t i = 1; i < p; i++)
    {
        if ((k * i) % p == 1)
        {
            return i;
        }
    }
    return -1;
}

template <typename T>
T min(T a, T b)
{
    return a < b ? a : b;
}

// ===--- RSA CIPHER ---========================================================
#define __RSA_CIPHER

int_t rsa_N(int_t p, int_t q)
{
    assert(is_prime(p) && "p must be prime");
    assert(is_prime(q) && "q must be prime");
    return p * q;
}

int_t rsa_t(int_t p, int_t q)
{
    assert(is_prime(p) && "p must be prime");
    assert(is_prime(q) && "q must be prime");
    return (p - 1) * (q - 1);
}

int_t rsa_cif_key(int_t t)
{
    std::vector<int_t> lst;
    for (int_t i = 2; i < t - 1; i++)
    {
        if (is_prime(i) && t % i != 0)
        {
            lst.push_back(i);
        }
    }
    return lst[rand() % lst.size()];
}

int_t rsa_dcif_key(int_t cif_key, int_t t)
{
    for (int_t i = 1; i < t; i++)
    {
        if ((cif_key * i) % t == 1)
        {
            return i;
        }
    }
    return -1;
}

int_t rsa_cif(int_t x, int_t key, int_t N)
{
    return pow_mod(x, key, N);
}

int_t rsa_cif(byte_t x, int_t key, int_t N)
{
    return pow_mod(x, key, N);
}

/*
!! Allocates memory for the result
*/
void rsa_cif(int_t *data, size_t data_size,
             int_t **cif, size_t *cif_size,
             int_t key, int_t N)
{
    int_t *res = ALLOC(int_t, 2 * data_size);
    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = rsa_cif(data[i], key, N);
    }
    *cif = res;
    *cif_size = data_size;
}

/*
!! Allocates memory for the result
*/
void rsa_cif(byte_t *data, size_t data_size,
             int_t **cif, size_t *cif_size,
             int_t key, int_t N)
{
    int_t *res = ALLOC(int_t, 2 * data_size);
    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = rsa_cif((int_t)data[i], key, N);
    }
    *cif = res;
    *cif_size = data_size;
}

int_t rsa_dcif(int_t x, int_t key, int_t N)
{
    return pow_mod(x, key, N);
}

/*
!! Allocates memory for the result
*/
void rsa_dcif(int_t *cif, size_t cif_size,
              int_t **data, size_t *data_size,
              int_t key, int_t N)
{
    int_t *res = ALLOC(int_t, cif_size);
    for (size_t i = 0; i < cif_size; i++)
    {
        res[i] = rsa_dcif(cif[i], key, N);
    }
    *data = res;
    *data_size = cif_size;
}

/*
!! Allocates memory for the result
*/
void rsa_dcif(int_t *cif, size_t cif_size,
              byte_t **data, size_t *data_size,
              int_t key, int_t N)
{
    byte_t *res = ALLOC(byte_t, cif_size);
    for (size_t i = 0; i < cif_size; i++)
    {
        res[i] = rsa_dcif(cif[i], key, N);
    }
    *data = res;
    *data_size = cif_size;
}

// ===--- ELGAMAL CIPHER ---====================================================
#define __ELGAMAL_CIPHER

int_t __elg_session_key_x(int_t p)
{
    return rand() % (p - 1) + 1;
}

int_t __elg_y(int_t g, int_t x, int_t p)
{
    return pow_mod(g, x, p);
}

void elg_make_private_key(int_t *key_x, int_t p)
{
    *key_x = __elg_session_key_x(p);
}

void elg_make_public_key(int_t *key_y, int_t *key_g, int_t x, int_t p)
{
    *key_g = primitive_root_mod(p);
    *key_y = __elg_y(*key_g, x, p);
}

void elg_cif(int_t *a, int_t *b, int_t m, int_t key_y, int_t key_g, int_t p)
{
    int_t k = __elg_session_key_x(p);
    *a = pow_mod(key_g, k, p);
    *b = (m * pow_mod(key_y, k, p)) % p;
}

/*
!! Allocates memory for the result
*/
void elg_cif(int_t *data, size_t data_size,
             int_t **cif, size_t *cif_size,
             int_t key_y, int_t key_g, int_t p)
{
    int_t *res = ALLOC(int_t, data_size << 1);
    int_t a, b;
    for (size_t i = 0; i < data_size; i++)
    {
        elg_cif(&a, &b, data[i], key_y, key_g, p);
        res[i << 1] = a;
        res[(i << 1) + 1] = b;
    }
    *cif = res;
    *cif_size = data_size << 1;
}

int_t elg_dcif(int_t a, int_t b, int_t key_x, int_t p)
{
    return (b * pow_mod(a, p - 1 - key_x, p)) % p;
}

/*
!! Allocates memory for the result
*/
void elg_dcif(int_t *cif, size_t cif_size,
              int_t **data, size_t *data_size,
              int_t key_x, int_t p)
{
    int_t *res = ALLOC(int_t, cif_size >> 1);
    for (size_t i = 0; i < cif_size; i += 2)
    {
        res[i >> 1] = elg_dcif(cif[i], cif[i + 1], key_x, p);
    }
    *data = res;
    *data_size = cif_size >> 1;
}

// ===--- ELGAMAL SIGNATURE ---=================================================
#define __ELGAMAL_SIGNATURE

int_t __elgsig_k(int_t p)
{
    return coprime(p - 1);
}

int_t __elgsig_a(int_t g, int_t k, int_t p)
{
    return pow_mod(g, k, p);
}

int_t __elgsig_reverse_k(int_t k, int_t p)
{
    return get_multiplicative_inverse(k, p - 1);
}

int_t __elgsig_b(int_t m, int_t k, int_t x, int_t a, int_t p)
{
    int_t mmod = (__elgsig_reverse_k(k, p) * (m - x * a)) % (p - 1);
    // 'C' peculiarity about mod operation:
    return mmod >= 0 ? mmod : mmod + p - 1;
}

void elgsig_make(int_t *a, int_t *b,
                 int_t key_x, int_t key_g,
                 int_t p, int_t m)
{
    int_t k = __elgsig_k(p);
    *a = __elgsig_a(key_g, k, p);
    *b = __elgsig_b(m, k, key_x, *a, p);
}

void elgsig_make(int_t *data, size_t data_size,
                 int_t **cif, size_t *cif_size,
                 int_t key_y, int_t key_g, int_t p)
{
    int_t *res = ALLOC(int_t, data_size << 1);
    int_t a, b;
    for (size_t i = 0; i < data_size; i++)
    {
        elgsig_make(&a, &b, key_y, key_g, p, data[i]);
        res[i << 1] = a;
        res[(i << 1) + 1] = b;
    }
    *cif = res;
    *cif_size = data_size << 1;
}

bool elgsig_check(int_t key_y, int_t key_g,
                  int_t a, int_t b, int_t p, int_t m)
{
    return (pow_mod(key_y, a, p) * pow_mod(a, b, p)) % p == pow_mod(
                                                                key_g, m, p);
}

bool elgsig_check(int_t *cif, size_t cif_size,
                  int_t key_y, int_t key_g, int_t p,
                  int_t *data, size_t data_size)
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

typedef struct des_key_sets
{
    byte_t k[8];
    byte_t c[4];
    byte_t d[4];
} des_key_sets;

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

bool __des_is_key_acceptable(byte_t *key)
{
    return !__des_is_key_weak(key) && !__des_is_key_semi_weak(key);
}

/*
main_key - 64 bit key
key_sets - array of (+1)16 key sets
*/
void __des_generate_sub_keys(byte_t *main_key, des_key_sets *key_sets)
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

/*
data_block - 64 bit block (8 bytes)
processed_block - 64 bit block (8 bytes)
key_sets - array of (+1)16 key sets
mode - 1 for encryption, 0 for decryption
*/
void __des_process_data_block(byte_t *data_block,
                              byte_t *processed_block,
                              des_key_sets *key_sets,
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

void __des_encrypt_block(byte_t *data_block,
                         byte_t *processed_block,
                         des_key_sets *key_sets)
{
    __des_process_data_block(data_block, processed_block, key_sets, DES_ENCRYPTION_MODE);
}

void __des_decrypt_block(byte_t *data_block,
                         byte_t *processed_block,
                         des_key_sets *key_sets)
{
    __des_process_data_block(data_block, processed_block, key_sets, DES_DECRYPTION_MODE);
}

void des_generate_key(byte_t *key)
{
    srand(time(0));
    do
    {
        int i;
        for (i = 0; i < 8; i++)
        {
            key[i] = rand() % 255;
        }
    } while (!__des_is_key_acceptable(key));
}

void des_encrypt(byte_t *data, size_t data_size,
                 byte_t *enc_data, size_t *enc_data_size,
                 byte_t *des_key)
{
    short int bytes_written;
    unsigned long block_count = 0, number_of_blocks;
    byte_t *data_block = ALLOC(byte_t, 8);
    byte_t *processed_block = ALLOC(byte_t, 8);
    des_key_sets *key_sets = ALLOC(des_key_sets, 17);

    __des_generate_sub_keys(des_key, key_sets);

    number_of_blocks = data_size / 8 + (data_size % 8 ? 1 : 0);

    for (block_count = 0; block_count < number_of_blocks; block_count++)
    {
        bytes_written = 0;
        for (int i = 0; i < 8; i++)
        {
            data_block[i] = 0;
        }

        for (int i = 0; i < 8; i++)
        {
            if ((size_t)bytes_written < data_size)
            {
                data_block[i] = data[block_count * 8 + bytes_written];
            }
            else if ((size_t)bytes_written == data_size)
            {
                data_block[i] = 0x80;
            }
            else
            {
                data_block[i] = 0;
            }
            bytes_written++;
        }

        __des_encrypt_block(data_block, processed_block, key_sets);

        for (int i = 0; i < 8; i++)
        {
            enc_data[block_count * 8 + i] = processed_block[i];
        }
    }

    *enc_data_size = data_size;
    free(data_block);
    free(processed_block);
    free(key_sets);
}

void des_decrypt(byte_t *data, size_t data_size,
                 byte_t *dec_data, size_t *dec_data_size,
                 byte_t *des_key)
{
    short int bytes_written;
    unsigned long block_count = 0, number_of_blocks;
    byte_t *data_block = ALLOC(byte_t, 8);
    byte_t *processed_block = ALLOC(byte_t, 8);
    des_key_sets *key_sets = ALLOC(des_key_sets, 17);

    __des_generate_sub_keys(des_key, key_sets);

    number_of_blocks = data_size / 8 + (data_size % 8 ? 1 : 0);

    for (block_count = 0; block_count < number_of_blocks; block_count++)
    {
        bytes_written = 0;
        for (int i = 0; i < 8; i++)
        {
            data_block[i] = 0;
        }

        for (int i = 0; i < 8; i++)
        {
            if ((size_t)bytes_written < data_size)
            {
                data_block[i] = data[block_count * 8 + bytes_written];
            }
            else if ((size_t)bytes_written == data_size)
            {
                data_block[i] = 0x80;
            }
            else
            {
                data_block[i] = 0;
            }
            bytes_written++;
        }

        __des_decrypt_block(data_block, processed_block, key_sets);

        for (int i = 0; i < 8; i++)
        {
            dec_data[block_count * 8 + i] = processed_block[i];
        }
    }

    *dec_data_size = data_size;
    free(data_block);
    free(processed_block);
    free(key_sets);
}

// ===--- BENCHMARKS ---========================================================
#define __BENCHMARKS

void rsa_bench()
{
    std::cout << "RSA BENCHMARK: ";
    auto bench_time = GET_CURR_TIME;
    int_t epochs = 200;
    int_t enc_epochs = 2000;
    int_t p = 257; // 257
    int_t q = 503; // 503

    srand(time(0));
    assert(is_prime(p) && is_prime(q) && "p and q must be prime");
    int_t _N = rsa_N(p, q);
    int_t _t = rsa_t(p, q);
    auto time = GET_CURR_TIME;
    int_t cif;
    for (int_t i = 0; i < epochs; i++)
    {
        cif = rsa_cif_key(_t);
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
    int_t dcif;
    for (int_t i = 0; i < epochs; i++)
    {
        dcif = rsa_dcif_key(cif, _t);
    }

#ifdef TESTS_VERBOSE
    auto rsa_dcif_t = GET_TIME_DIFF(time, GET_CURR_TIME);
#endif // TESTS_VERBOSE

    int_t num = 123;
    time = GET_CURR_TIME;
    int_t encd;
    for (int_t i = 0; i < enc_epochs; i++)
    {
        encd = rsa_cif(num, cif, _N);
    }

#ifdef TESTS_VERBOSE
    auto encd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
#endif // TESTS_VERBOSE

    time = GET_CURR_TIME;
    int_t decd;
    for (int_t i = 0; i < enc_epochs; i++)
    {
        decd = rsa_dcif(encd, dcif, _N);
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
           float(rsa_cif_t) / 1000000 / epochs);
    printf("dcif\t\xB3");
    std::cout << dcif << std::endl;
    printf("d_key_t\t\xB3%.6fms\n",
           float(rsa_dcif_t) / 1000000 / epochs);
    printf("sum_t\t\xB3%.6fms\n",
           float(rsa_dcif_t + rsa_cif_t) / 1000000 / epochs);
    printf("\nnum\t\xB3");
    std::cout << num << std::endl;
    printf("enc\t\xB3");
    std::cout << encd << std::endl;
    printf("enc_t\t\xB3%.6fms\n",
           float(encd_t) / 1000000 / enc_epochs);
    printf("dec\t\xB3");
    std::cout << decd << std::endl;
    printf("dec_t\t\xB3%.6fms\n",
           float(decd_t) / 1000000 / enc_epochs);
    printf("sum_t\t\xB3%.6fms\n",
           float(decd_t + encd_t) / 1000000 / enc_epochs);
#endif // TESTS_VERBOSE
    bool res = decd == num;
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(GET_TIME_DIFF(bench_time, GET_CURR_TIME)) / 1000000);
}

void elg_bench()
{
    std::cout << "ELG BENCHMARK: ";
    srand(time(0));
    int_t p = 503;
    int_t m = 20;
    assert(is_prime(p) && "p must be prime");
    assert(m <= p && "m must be less than p");

    int pr_k_iter = 20000000;
    int pu_k_iter = 2000;
    int cif_iter = 20000;
    int dcif_iter = 20000;

    auto total_start = GET_CURR_TIME;
    int_t key_x, key_y, key_g, a, b, decd;

#ifdef TESTS_VERBOSE
    auto time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_make_private_key(&key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_make_public_key(&key_y, &key_g, key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < cif_iter; i++)
    {
        elg_cif(&a, &b, m, key_y, key_g, p);
    }

#ifdef TESTS_VERBOSE
    auto cif_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < dcif_iter; i++)
    {
        decd = elg_dcif(a, b, key_x, p);
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
           float(pr_k_time) / 1000000 / pr_k_iter);
    printf("\npublic key:\ny\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("pu_k_t\t\xB3%.6fms\n",
           float(pu_k_time) / 1000000 / pu_k_iter);
    printf("\ncif:\na\t\xB3");
    std::cout << a << std::endl;
    printf("b\t\xB3");
    std::cout << b << std::endl;
    printf("cif_t\t\xB3%.6fms\n",
           float(cif_time) / 1000000 / cif_iter);
    printf("\ndec:\t\xB3");
    std::cout << decd << std::endl;
    printf("dec_t\t\xB3%.6fms\n",
           float(decd_t) / 1000000 / dcif_iter);
#endif // TESTS_VERBOSE

    bool res = decd == m;
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(total_t) / 1000000);
}

void elgsig_bench()
{
    std::cout << "ELGSIG BENCHMARK: ";
    srand(time(0));

    int pr_k_iter = 20000000;
    int pu_k_iter = 2000;
    int sig_iter = 20000;

    int_t p = 503;
    int_t m = 20;

    assert(is_prime(p) && "p must be prime");

    int_t key_x, key_y, key_g, a, b;
    auto total_start = GET_CURR_TIME;
#ifdef TESTS_VERBOSE
    auto time = GET_CURR_TIME;
#endif // TESTS_VERBOSE
    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_make_private_key(&key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_make_public_key(&key_y, &key_g, key_x, p);
    }

#ifdef TESTS_VERBOSE
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
#endif // TESTS_VERBOSE

    for (int_t i = 0; i < sig_iter; i++)
    {
        elgsig_make(&a, &b, key_x, key_g, p, m);
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
           float(pr_k_time) / 1000000 / pr_k_iter);
    printf("\npublic key:\ny\t\xB3");
    std::cout << key_y << std::endl;
    printf("g\t\xB3");
    std::cout << key_g << std::endl;
    printf("p\t\xB3");
    std::cout << p << std::endl;
    printf("pu_k_t\t\xB3%.6fms\n",
           float(pu_k_time) / 1000000 / pu_k_iter);
    printf("\nsig:\na\t\xB3");
    std::cout << a << std::endl;
    printf("b\t\xB3");
    std::cout << b << std::endl;
    printf("sig_t\t\xB3%.6fms\n",
           float(sig_time) / 1000000 / sig_iter);

#endif // TESTS_VERBOSE
    bool res = elgsig_check(key_y, key_g, a, b, p, m);
    printf(res ? PASSED_TIME_FMT : FAILED_STR, float(total_t) / 1000000);
}

// ===--- SERVICE ---===========================================================
#define __SERVICE

int_t hex_num_len(int_t num)
{
    int_t res = 1;
    while (num > 15)
    {
        num >>= 4;
        res++;
    }
    return res;
}

int_t dec_num_len(int_t num)
{
    int_t res = 1;
    while (num > 9)
    {
        num /= 10;
        res++;
    }
    return res;
}

void dump_data_to_dec_file(int_t *data, size_t data_size,
                           int_t N, const char *file_name)
{
    size_t num_len = dec_num_len(N);
    FILE *file = fopen(file_name, "w");
    for (size_t i = 0; i < data_size; i++)
    {
        for (size_t j = 0; j < num_len - dec_num_len(data[i]); j++)
        {
            fprintf(file, "0");
        }
        fprintf(file, "%d", data[i]);
    }
    fclose(file);
}

/*
!! Allocates memory for the result
*/
void dump_data_to_dec_str(int_t *data, size_t data_size,
                          int_t N, char **str)
{
    size_t num_len = dec_num_len(N);
    char *res = ALLOC(char, data_size *num_len);
    for (size_t i = 0; i < data_size; i++)
    {
        for (size_t j = 0; j < num_len - dec_num_len(data[i]); j++)
        {
            *res = '0';
            res++;
        }
        sprintf(res, "%d", data[i]);
        res += dec_num_len(data[i]);
    }
    res -= data_size * num_len;
    *str = res;
}

void dump_data_to_hex_file(int_t *data, size_t data_size, int_t N,
                           const char *file_name)
{
    size_t num_len = hex_num_len(N);
    FILE *file = fopen(file_name, "w");
    for (size_t i = 0; i < data_size; i++)
    {
        fprintf(file, "%0*X", (int)num_len, data[i]);
    }
    fclose(file);
}

/*
!! Allocates memory for the result
*/
void dump_data_to_hex_str(int_t *data, size_t data_size, int_t N, char **str)
{
    size_t num_len = hex_num_len(N);
    char *res = ALLOC(char, data_size *num_len);
    for (size_t i = 0; i < data_size; i++)
    {
        sprintf(res, "%0*X", (int)num_len, data[i]);
        res += num_len;
    }
    res -= data_size * num_len;
    *str = res;
}

void dump_data_to_bin_file(int_t *data, size_t data_size, const char *file_name)
{
    FILE *file = fopen(file_name, "wb");
    fwrite(data, sizeof(int_t), data_size, file);
    fclose(file);
}

/*
!! Allocates memory for the result
*/
void read_dump_from_dec_file(int_t **data, size_t *data_size, int_t N,
                             const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = (char *)malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);
    size_t num_len = dec_num_len(N);
    size_t num_count = file_size / num_len;
    int_t *res = (int_t *)malloc(num_count * sizeof(int_t));
    for (size_t i = 0; i < num_count; i++)
    {
        int_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = num * 10 + buffer[i * num_len + j] - '0';
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
    free(buffer);
}

/*
!! Allocates memory for the result
*/
void read_dump_from_hex_file(int_t **data, size_t *data_size, int_t N,
                             const char *file_name)
{
    FILE *file = fopen(file_name, "r");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = (char *)malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);
    size_t num_len = hex_num_len(N);
    size_t num_count = file_size / num_len;
    int_t *res = (int_t *)malloc(num_count * sizeof(int_t));
    for (size_t i = 0; i < num_count; i++)
    {
        int_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = (num << 4) + buffer[i * num_len + j] - '0' -
                  ((int_t)((buffer[i * num_len + j] >= 'A') &&
                           (buffer[i * num_len + j] <= 'F')) *
                   7) -
                  ((int_t)((buffer[i * num_len + j] >= 'a') &&
                           (buffer[i * num_len + j] <= 'f')) *
                   39);
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
    free(buffer);
}

/*
!! Allocates memory for the result
*/
void read_dump_from_bin_file(int_t **data, size_t *data_size, const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    int_t *res = (int_t *)malloc(file_size);
    fread(res, sizeof(int_t), file_size / sizeof(int_t), file);
    fclose(file);
    *data = res;
    *data_size = file_size / sizeof(int_t);
}

template <typename T>
void print_array(T *data, size_t data_size)
{
    printf("{");
    for (size_t i = 0; i < data_size - 1; i++)
    {
        printf("%u, ", data[i]);
    }
    printf("%u}\n", data[data_size - 1]);
}

template <typename T>
void print_array_hex(T *data, size_t data_size)
{
    printf("(%lld){", data_size);
    for (size_t i = 0; i < data_size - 1; i++)
    {
        printf("0x%0*X, ", (int)sizeof(T) * 2, data[i]);
    }
    printf("0x%0*X}\n", (int)sizeof(T) * 2, data[data_size - 1]);
}

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

bool cmp_arrays(int_t *arr1, size_t arr1_size, int_t *arr2, size_t arr2_size)
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

/*
!! Allocates memory for the result
*/
void array_to_ascii(int_t *data, size_t data_size, char **str)
{
    char *res = CALLOC(char, data_size);
    for (size_t i = 0; i < data_size; i++)
    {
        res[i] = (char)data[i];
    }
    *str = res;
}

/*
!! Allocates memory for the result
*/
void acsii_to_array(char *str, int_t **data, size_t *data_size)
{
    size_t str_len = strlen(str);
    int_t *res = ALLOC(int_t, str_len);
    for (size_t i = 0; i < str_len; i++)
    {
        res[i] = (int_t)str[i];
    }
    *data = res;
    *data_size = str_len;
}

/*
!! Allocates memory for the result
*/
void parse_str_to_ints(char *str, int_t **data, size_t *data_size)
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
    std::vector<int_t> lst;
    char *token = strtok(str, " ");
    while (token != NULL)
    {
        lst.push_back(atoi(token));
        token = strtok(NULL, " ");
    }
    *data_size = lst.size();
    SCRAP_VECTOR(*data, lst, int_t);
}

void parse_cif_to_ints(char *str, int_t **data, size_t *data_size, int_t N)
{
    // chop str to N-sized parts, then atoi them
    size_t num_len = dec_num_len(N);
    size_t num_count = strlen(str) / num_len;
    int_t *res = ALLOC(int_t, num_count);
    for (size_t i = 0; i < num_count; i++)
    {
        int_t num = 0;
        for (size_t j = 0; j < num_len; j++)
        {
            num = num * 10 + str[i * num_len + j] - '0';
        }
        res[i] = num;
    }
    *data = res;
    *data_size = num_count;
}

bool is_array_ascii(int_t *data, size_t data_size)
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

bool is_array_contains_alpha(int_t *data, size_t data_size)
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

// ===--- TESTS ---=============================================================
#define __TESTS

#ifndef TESTS_ENABLED

void test_rsa_array(){};
void test_elg_array(){};
void test_elgsig_array(){};

#else // TESTS_ENABLES

void test_rsa_array()
{
    int_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    int_t *cif;
    size_t cif_size;
    int_t *dec;
    size_t dec_size;

    int_t p = 13;
    int_t q = 113;
    int_t N = rsa_N(p, q);
    int_t t = rsa_t(p, q);
    int_t cif_key = rsa_cif_key(t);
    int_t dcif_key = rsa_dcif_key(cif_key, t);

    printf("TEST RSA ARRAY: ");
    rsa_cif(data, data_size, &cif, &cif_size, cif_key, N);
    rsa_dcif(cif, cif_size, &dec, &dec_size, dcif_key, N);
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

    free(cif);
    free(dec);
}

void test_elg_array()
{
    int_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    int_t *cif;
    size_t cif_size;
    int_t *dec;
    size_t dec_size;

    int_t p = 503;

    int_t key_x, key_y, key_g;

    elg_make_private_key(&key_x, p);
    elg_make_public_key(&key_y, &key_g, key_x, p);
    elg_cif(data, data_size, &cif, &cif_size, key_y, key_g, p);
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

    free(cif);
    free(dec);
}

void test_elgsig_array()
{
    int_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    int_t *cif;
    size_t cif_size;

    int_t p = 503;

    int_t key_x, key_y, key_g;

    elg_make_private_key(&key_x, p);
    elg_make_public_key(&key_y, &key_g, key_x, p);
    elgsig_make(data, data_size, &cif, &cif_size, key_x, key_g, p);
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

    free(cif);
}

#endif // TESTS_ENABLED

// ===--- INTERFACE ---=========================================================
#define __INTERFACE

void main_case_rsa_genkey()
{
    printf(RSA_STR);
    int_t cif_key;
    int_t dcif_key;
    int_t *cif;
    size_t cif_size;
    int_t *data;
    size_t data_size;
    char *str_buf;
    printf("First prime number (p): ");
    int_t p;
    std::cin >> p;
    printf("Second prime number (q): ");
    int_t q;
    std::cin >> q;
    int_t N = rsa_N(p, q);
    int_t t = rsa_t(p, q);
    cif_key = rsa_cif_key(t);
    dcif_key = rsa_dcif_key(cif_key, t);
    std::cout << "N: " << N << std::endl;
    std::cout << "t: " << t << std::endl;
    std::cout << "Public key: " << cif_key << std::endl;
    std::cout << "Private key: " << dcif_key << std::endl;
    std::string input_str;
    std::cout << "Enter sequence to encode: " << std::endl;
    std::getline(std::cin >> std::ws, input_str);
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    rsa_cif(data, data_size, &cif, &cif_size, cif_key, N);
    dump_data_to_dec_str(cif, cif_size, N, &str_buf);
    std::cout << C_CYAN "Encoded sequence:" C_RESET " \n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_rsa_setkey()
{
    printf(RSA_STR);
    printf("Public key: ");
    int_t cif_key;
    std::cin >> cif_key;
    printf("N: ");
    int_t N;
    std::cin >> N;
    std::string input_str;
    std::cout << "Enter sequence to encode:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    int_t *cif;
    size_t cif_size;
    rsa_cif(data, data_size, &cif, &cif_size, cif_key, N);
    char *str_buf;
    dump_data_to_dec_str(cif, cif_size, N, &str_buf);
    std::cout << C_CYAN "Encoded sequence:" C_RESET " \n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_rsa_decode()
{
    printf(RSA_STR);
    printf("Private key: ");
    int_t prvt_key;
    std::cin >> prvt_key;
    printf("N: ");
    int_t N;
    std::cin >> N;
    std::string input_str;
    std::cout << "Enter sequence to decode:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    parse_cif_to_ints((char *)input_str.c_str(), &data, &data_size, N);
    int_t *dcif;
    size_t dcif_size;
    rsa_dcif(data, data_size, &dcif, &dcif_size, prvt_key, N);
    std::cout << C_CYAN "Decoded sequence:" C_RESET " \n";
    print_array(dcif, dcif_size);
    if (is_array_ascii(dcif, dcif_size))
    {
        char *str_buf;
        array_to_ascii(dcif, dcif_size, &str_buf);
        std::cout << C_CYAN "Decoded sequence (ASCII):" C_RESET " \n"
                  << str_buf << std::endl;
        free(str_buf);
    }
    free(data);
    free(dcif);
}

void main_case_elg_genkey()
{
    printf(ELGAMAL_STR);
    int_t key_x, key_y, key_g;
    int_t p;
    printf("N: ");
    std::cin >> p;
    elg_make_private_key(&key_x, p);
    elg_make_public_key(&key_y, &key_g, key_x, p);
    std::cout << "Private key (x): " << key_x << std::endl;
    std::cout << "Public key (y): " << key_y << std::endl;
    std::cout << "Generator (g): " << key_g << std::endl;
    std::string input_str;
    std::cout << "Enter sequence to encode:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    int_t *cif;
    size_t cif_size;
    elg_cif(data, data_size, &cif, &cif_size, key_y, key_g, p);
    char *str_buf;
    dump_data_to_dec_str(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Encoded sequence:" C_RESET " \n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_elg_setkey()
{
    printf(ELGAMAL_STR);
    printf("Public key (y): ");
    int_t key_y;
    std::cin >> key_y;
    printf("Generator (g): ");
    int_t key_g;
    std::cin >> key_g;
    printf("N: ");
    int_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to encode:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    int_t *cif;
    size_t cif_size;
    elg_cif(data, data_size, &cif, &cif_size, key_y, key_g, p);
    char *str_buf;
    dump_data_to_dec_str(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Encoded sequence:" C_RESET " \n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_elg_decode()
{
    printf(ELGAMAL_STR);
    printf("Private key (x): ");
    int_t prvt_key;
    std::cin >> prvt_key;
    printf("N: ");
    int_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to decode:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    parse_cif_to_ints((char *)input_str.c_str(), &data, &data_size, p);
    int_t *dcif;
    size_t dcif_size;
    elg_dcif(data, data_size, &dcif, &dcif_size, prvt_key, p);
    std::cout << C_CYAN "Decoded sequence:" C_RESET " \n";
    print_array(dcif, dcif_size);
    if (is_array_ascii(dcif, dcif_size))
    {
        char *str_buf;
        array_to_ascii(dcif, dcif_size, &str_buf);
        std::cout << C_CYAN "Decoded sequence (ASCII):" C_RESET " \n"
                  << str_buf << std::endl;
        free(str_buf);
    }
    free(data);
    free(dcif);
}

void main_case_elgsig_genkey()
{
    printf(ELGSIG_STR);
    int_t key_x, key_y, key_g;
    int_t p;
    printf("N: ");
    std::cin >> p;
    elg_make_private_key(&key_x, p);
    elg_make_public_key(&key_y, &key_g, key_x, p);
    std::cout << "Private key (x): " << key_x << std::endl;
    std::cout << "Public key (y): " << key_y << std::endl;
    std::cout << "Generator (g): " << key_g << std::endl;
    std::string input_str;
    std::cout << "Enter sequence to sign:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    int_t *cif;
    size_t cif_size;
    elgsig_make(data, data_size, &cif, &cif_size, key_x, key_g, p);
    char *str_buf;
    dump_data_to_dec_str(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Signature:" C_RESET "\n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_elgsig_setkey()
{
    printf(ELGSIG_STR);
    printf("Private key (x): ");
    int_t key_x;
    std::cin >> key_x;
    printf("Generator (g): ");
    int_t key_g;
    std::cin >> key_g;
    printf("N: ");
    int_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to sign:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    int_t *cif;
    size_t cif_size;
    elgsig_make(data, data_size, &cif, &cif_size, key_x, key_g, p);
    char *str_buf;
    dump_data_to_dec_str(cif, cif_size, p, &str_buf);
    std::cout << C_CYAN "Signature:" C_RESET "\n"
              << str_buf << std::endl;
    free(data);
    free(cif);
}

void main_case_elgsig_check()
{
    printf(ELGSIG_STR);
    printf("Public key (y): ");
    int_t key_y;
    std::cin >> key_y;
    printf("Generator (g): ");
    int_t key_g;
    std::cin >> key_g;
    printf("N: ");
    int_t p;
    std::cin >> p;
    std::string input_str;
    std::cout << "Enter sequence to check:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *data;
    size_t data_size;
    if (is_str_contains_alpha((char *)input_str.c_str()))
    {
        acsii_to_array((char *)input_str.c_str(), &data, &data_size);
    }
    else
    {
        parse_str_to_ints((char *)input_str.c_str(), &data, &data_size);
    }
    std::cout << "Enter signature:\n";
    std::getline(std::cin >> std::ws, input_str);
    int_t *cif;
    size_t cif_size;
    parse_cif_to_ints((char *)input_str.c_str(), &cif, &cif_size, p);
    bool res = elgsig_check(cif, cif_size, key_y, key_g, p, data, data_size);
    std::cout << (res ? C_GREEN "Signature is valid" C_RESET " "
                      : C_RED "Signature is invalid" C_RESET " ")
              << std::endl;
    free(data);
    free(cif);
}

void main_interface()
{
    ime_enter_alt_screen();
    // ime_exit_alt_screen();
    ime_clear_screen();

    printf(IME_ESC IME_RGB_COLOR(0, 255, 255) IME_ESC_END
           "CIFS.CPP" C_RESET " \n");
    printf("===--- CIFS \n");
    printf("  1) RSA\n");
    printf("  2) ELGAMAL\n");
    printf("  3) ELGAMAL SIGNATURE\n");
    printf("===--- BENCHMARKS \n");
    printf("  4) RSA\n");
    printf("  5) ELGAMAL\n");
    printf("  6) ELGAMAL SIGNATURE\n");
    printf("  7) Run all tests\n");

    printf(INPUT_STR);
    int input;
    std::cin >> input;
    ime_clear_screen();

    switch (input)
    {
    case 1:
    {
        printf(RSA_STR);
        printf("===--- MODES \n");
        printf("  1) Generate keys & Encode\n");
        printf("  2) Enter key & Encode\n");
        printf("  3) Decode\n");

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
            main_case_rsa_setkey();
            break;
        }
        case 3:
        {
            main_case_rsa_decode();
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
    case 2:
    {
        printf(ELGAMAL_STR);
        printf("===--- MODES \n");
        printf("  1) Generate keys & Encode\n");
        printf("  2) Enter key & Encode\n");
        printf("  3) Decode\n");

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
            main_case_elg_setkey();
            break;
        }
        case 3:
        {
            main_case_elg_decode();
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
    case 3:
    {
        printf(ELGSIG_STR);
        printf("===--- MODES \n");
        printf("  1) Generate keys & Sign\n");
        printf("  2) Enter key & Sign\n");
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
            main_case_elgsig_setkey();
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
            return;
        }
        }
        break;
    }
    case 4:
    {
        ime_exit_alt_screen();
        rsa_bench();
        getchar();
        break;
    }
    case 5:
    {
        ime_exit_alt_screen();
        elg_bench();
        getchar();
        break;
    }
    case 6:
    {
        ime_exit_alt_screen();
        elgsig_bench();
        getchar();
        break;
    }
    case 7:
    {
        ime_exit_alt_screen();
        printf(TESTS_STR);
        test_rsa_array();
        test_elg_array();
        test_elgsig_array();
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

static const char *const usages[] = {
    "cifs [options] [[--] args]",
    "cifs [options]",
    "cifs",
    NULL,
};

bool str_eq(const char *str1, const char *str2)
{
    return strcmp(str1, str2) == 0;
}

void read_bin_file(byte_t **bytes, size_t *size, const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    assert(file != NULL && "Can't open file");
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *bytes = ALLOC(byte_t, *size);
    assert(*bytes != NULL && "Memory allocation failed");
    fread(*bytes, 1, *size, file);
    fclose(file);
}

void write_bin_file(const byte_t *bytes, size_t size, const char *file_name)
{
    FILE *file = fopen(file_name, "wb");
    assert(file != NULL && "Can't open file");
    fwrite(bytes, 1, size, file);
    fclose(file);
}

void split_array_to_bytes_N(int_t *data, size_t data_size,
                            byte_t **new_data, size_t *new_size,
                            int_t N)
{
    size_t byte_len = (hex_num_len(N) + 1) / 2; // 2 hex symbols per byte
    *new_size = data_size * byte_len;
    *new_data = ALLOC(byte_t, *new_size);
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

/*
!! Allocates memory for the result
*/
template <typename T>
void merge_array_bytes_N(byte_t *data, size_t data_size,
                         T **new_data, size_t *new_size,
                         int_t N)
{
    size_t num_len = (hex_num_len(N) + 1) / 2; // 2 hex symbols per byte
    *new_size = data_size / num_len;
    *new_data = ALLOC(T, *new_size);
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

/*
!! Allocates memory for the result
*/
void read_bin_file_chunk(byte_t **bytes, size_t *size,
                         size_t start, size_t end,
                         const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    if (file == NULL)
    {
        if (!log_quiet_lvl)
        {
            std::cerr << "Can't open file: " << file_name << std::endl;
        }
        exit(1);
    }
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
    assert(*bytes != NULL && "Memory allocation failed");
    fseek(file, start, SEEK_SET);
    fread(*bytes, 1, *size, file);
    fclose(file);
}

void write_bin_file_chunk(const byte_t *bytes, size_t size,
                          size_t start, const char *file_name)
{
    FILE *file = fopen(file_name, "r+b");
    if (file == NULL)
    {
        file = fopen(file_name, "wb");
    }
    if (file == NULL)
    {
        if (!log_quiet_lvl)
        {
            std::cerr << "Can't open file: " << file_name << std::endl;
        }
        exit(1);
    }
    fseek(file, start, SEEK_SET);
    fwrite(bytes, 1, size, file);
    fclose(file);
}

size_t count_file_chunks(const char *file_name, size_t chunk_size)
{
    FILE *file = fopen(file_name, "rb");
    assert(file != NULL && "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return (file_size + chunk_size - 1) / chunk_size;
}

size_t file_size(const char *file_name)
{
    FILE *file = fopen(file_name, "rb");
    assert(file != NULL && "Can't open file");
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fclose(file);
    return file_size;
}

// ===--- <DEV> ---=============================================================

void dev_func()
{
    // Key gen
    byte_t *des_key_ = ALLOC(byte_t, 8);
    des_generate_key(des_key_);
    printf("Key: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%02X ", des_key_[i]);
    }
    printf("\n");
    byte_t data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    size_t data_size = sizeof(data) / sizeof(data[0]);
    printf("Data: ");
    print_array_hex(data, data_size);

    // Encrypt
    byte_t *enc_data = ALLOC(byte_t, data_size);
    size_t enc_size;

    des_encrypt(data, data_size, enc_data, &enc_size, des_key_);

    printf("Encrypted data: ");
    print_array_hex(enc_data, enc_size);

    // Decrypt
    byte_t *dec_data = ALLOC(byte_t, data_size);
    size_t dec_size;

    des_decrypt(enc_data, enc_size, dec_data, &dec_size, des_key_);

    printf("Decrypted data: ");
    print_array_hex(dec_data, dec_size);
}

// ===--- </DEV> ---============================================================

int main(int argc, const char **argv)
{
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
        int encode = 0;
        int decode = 0;
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
                       "mode to run ('rsa'- RSA, 'elg' - ElGamal, "
                       "'elgsig' - ElGamal signature)",
                       NULL, 0, 0),

            OPT_GROUP(C_HEADER "RSA" C_RESET " "),
            OPT_BOOLEAN('e', "encode", &encode, "encode data", NULL, 0, 0),
            OPT_BOOLEAN('d', "decode", &decode, "decode data", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "output", &output,
                       "path to output file", NULL, 0, 0),
            OPT_STRING('k', "key", &key, "encoding/decoding key", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),

            OPT_GROUP(C_HEADER "ElGamal" C_RESET " "),
            OPT_BOOLEAN('e', "encode", &encode, "encode data", NULL, 0, 0),
            OPT_BOOLEAN('d', "decode", &decode, "decode data", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "output", &output,
                       "path to output file", NULL, 0, 0),
            OPT_STRING('k', "key", &key,
                       "encoding / decoding key", NULL, 0, 0),
            OPT_STRING('g', "generator", &add_key,
                       "generator key (encoding)", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),

            OPT_GROUP(C_HEADER "ElGamal signature" C_RESET " "),
            OPT_BOOLEAN('s', "sign", &encode, "sign data", NULL, 0, 0),
            OPT_BOOLEAN('c', "check", &decode, "check sign", NULL, 0, 0),
            OPT_STRING('f', "file", &file, "path to input file", NULL, 0, 0),
            OPT_STRING('o', "signature", &output,
                       "path to output file / signature", NULL, 0, 0),
            OPT_STRING('k', "key", &key, "signing / checking key", NULL, 0, 0),
            OPT_STRING('g', "generator", &add_key,
                       "generator key (signing)", NULL, 0, 0),
            OPT_STRING('n', "n", &ring, "N key", NULL, 0, 0),

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
        byte_t *data;
        size_t data_size;

        int_t *data_int;
        size_t data_int_size;

        int_t *cif;
        size_t cif_size;

        byte_t *dcif;
        size_t dcif_size;

        byte_t *bytes;
        size_t bytes_size;

        printf("DBG: %s\n", mode);
        if (str_eq("rsa", mode))
        {
            if (encode)
            {
                if (log_verbose_lvl)
                    printf("RSA encode\n");
                assert(file != NULL && "File path is required");
                assert(ring != 0 && "N key is required");
                assert(key != NULL && "Key is required");
                if (output == NULL)
                {
                    output = (char *)malloc(strlen(file) + 6);
                    strcpy((char *)output, file);
                    strcat((char *)output, ".ciph");
                }

                chunk_size = (file_size(file) / 100) + 1;
                chunk_count = count_file_chunks(file, chunk_size);

                auto iter = tq::tqdm(tq::range((size_t)0, chunk_count));
                iter.set_prefix("RSA encoding: ");

                if (log_quiet_lvl)
                    iter.set_ostream(devnull);
                if (log_common_lvl)
                    std::cout << "Chunk size: " << chunk_size << " bytes" << std::endl;
                for (auto i : iter)
                {
                    read_bin_file_chunk(&data, &data_size, i * chunk_size, (i + 1) * chunk_size, file);
                    if (log_verbose_lvl)
                    {
                        printf("Data: ");
                        print_array_hex(data, data_size);
                    }

                    rsa_cif(data, data_size, &cif, &cif_size, atoi(key), atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Encoded: ");
                        print_array_hex(cif, cif_size);
                    }

                    split_array_to_bytes_N(cif, cif_size,
                                           &bytes, &bytes_size,
                                           atoi(ring));
                    write_bin_file_chunk(bytes, bytes_size, i * chunk_size * ((hex_num_len(atoi(ring)) + 1) / 2), output);
                    if (log_verbose_lvl)
                    {
                        printf("Written: ");
                        print_array_hex(bytes, bytes_size);
                    }
                    free(data);
                    free(cif);
                    free(bytes);
                }
                std::cout << std::endl;
            }
            else if (decode)
            {
                assert(file != NULL && "File path is required");
                assert(ring != 0 && "N key is required");
                assert(key != NULL && "Key is required");
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
                    output = (char *)malloc(strlen(file) - 5);
                    strncpy((char *)output, file, strlen(file) - 5);
                    ((char *)output)[strlen(file) - 5] = '\0';
                }

                chunk_size = (file_size(file) / 100) + 1;
                chunk_count = count_file_chunks(file, chunk_size);

                auto iter = tq::tqdm(tq::range((size_t)0, chunk_count));
                iter.set_prefix("RSA decoding: ");

                if (log_quiet_lvl)
                    iter.set_ostream(devnull);
                if (log_common_lvl)
                    std::cout << "Chunk size: " << chunk_size << " bytes" << std::endl;
                for (auto i : iter)
                {
                    read_bin_file_chunk(&data, &data_size, i * chunk_size, (i + 1) * chunk_size, file);
                    if (log_verbose_lvl)
                    {
                        printf("Data: ");
                        print_array_hex(data, data_size);
                    }

                    merge_array_bytes_N<int_t>(data, data_size, &data_int, &data_int_size, atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Data int: ");
                        print_array(data_int, data_int_size);
                    }

                    rsa_dcif(data_int, data_int_size, &dcif, &dcif_size, atoi(key), atoi(ring));
                    if (log_verbose_lvl)
                    {
                        printf("Decoded: ");
                        print_array_hex(dcif, dcif_size);
                    }

                    write_bin_file_chunk(dcif, dcif_size, i * chunk_size / ((hex_num_len(atoi(ring)) + 1) / 2), output);
                    if (log_verbose_lvl)
                    {
                        printf("Written: ");
                        print_array_hex(dcif, dcif_size);
                    }
                    free(data);
                    free(data_int);
                    free(dcif);
                }
                free((void *)output);
            }
            else
            {
                printf(C_RED "Provide RSA mode '-e' or '-d'" C_RESET " \n");
                return 0;
            }
        }
        else if (str_eq("elg", mode))
        {
            printf("ElGamal\n");
        }
        else if (str_eq("elgsig", mode))
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