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

#define ADD_EXPORTS
#define IMECLUI_IMPLEMENTATION
#include "imeclui.h"

// ===--- CONFIG ---============================================================
#define __CONFIG

// Is tests to compile
#define TESTS_ENABLED

// Is tests & benchmarks verbose
#define TESTS_VERBOSE

// ===--- MACROS ---============================================================
#define __MACROS

// Time measurement
#define GET_CURR_TIME std::chrono::system_clock::now()
#define GET_TIME_DIFF(start, end) \
    std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()

// Preferrable allocators
#define ALLOC(T, size) ((T *)malloc((size) * sizeof(T)))
#define CALLOC(T, size) ((T *)calloc((size), sizeof(T)))

// Common integer type (signed)
#define int_t int

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

    int num = 123;
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
        fprintf(file, "%0*X", num_len, data[i]);
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
        sprintf(res, "%0*X", num_len, data[i]);
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

void print_array(int_t *data, size_t data_size)
{
    std::cout << "[";
    for (size_t i = 0; i < data_size - 1; i++)
    {
        std::cout << data[i] << ", ";
    }
    std::cout << data[data_size - 1] << "]" << std::endl;
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

// ===--- INTERFACE ---=========================================================
#define __INTERFACE

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

int main()
{
    ime_enter_alt_screen();
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
        printf("===--- MODES ---===\n");
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
            return 1;
        }
        }
        break;
    }
    case 2:
    {
        printf(ELGAMAL_STR);
        printf("===--- MODES ---===\n");
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
            return 1;
        }
        }
        break;
    }
    case 3:
    {
        printf(ELGSIG_STR);
        printf("===--- MODES ---===\n");
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
            return 1;
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
        printf(INVALID_INPUT_STR);
        return 1;
    }
    }

    getchar();
    ime_exit_alt_screen();
    return 0;
}