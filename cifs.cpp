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

#define GET_CURR_TIME std::chrono::system_clock::now()
#define GET_TIME_DIFF(start, end) \
    std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()

#define int_t int

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

int_t __rsa_N(int_t p, int_t q)
{
    return p * q;
}

int_t __rsa_t(int_t p, int_t q)
{
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

int_t rsa_dcif(int_t x, int_t key, int_t N)
{
    return pow_mod(x, key, N);
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

int_t elg_dcif(int_t a, int_t b, int_t key_x, int_t p)
{
    return (b * pow_mod(a, p - 1 - key_x, p)) % p;
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

void elgsig_make_signature(int_t *a, int_t *b,
                           int_t key_x, int_t key_g,
                           int_t p, int_t m)
{
    int_t k = __elgsig_k(p);
    *a = __elgsig_a(key_g, k, p);
    *b = __elgsig_b(m, k, key_x, *a, p);
}

bool elgsig_check_sig(int_t key_y, int_t key_g,
                      int_t a, int_t b, int_t p, int_t m)
{
    return (pow_mod(key_y, a, p) * pow_mod(a, b, p)) % p == pow_mod(
                                                                key_g, m, p);
}

// ===--- BENCHMARKS ---========================================================
#define __BENCHMARKS

void rsa_bench()
{
    std::cout << "RSA BENCHMARK" << std::endl;
    auto bench_time = GET_CURR_TIME;
    int_t epochs = 200;
    int_t enc_epochs = 2000;
    int_t p = 257; // 257
    int_t q = 503; // 503

    srand(time(0));
    assert(is_prime(p) && is_prime(q) && "p and q must be prime");
    int_t _N = __rsa_N(p, q);
    int_t _t = __rsa_t(p, q);
    auto time = GET_CURR_TIME;
    int_t cif;
    for (int_t i = 0; i < epochs; i++)
    {
        cif = rsa_cif_key(_t);
    }
    auto rsa_cif_t = GET_TIME_DIFF(time, GET_CURR_TIME);

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
    auto rsa_dcif_t = GET_TIME_DIFF(time, GET_CURR_TIME);
    printf("p\t\xB3");
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

    int num = 123;
    time = GET_CURR_TIME;
    int_t encd;
    for (int_t i = 0; i < enc_epochs; i++)
    {
        encd = rsa_cif(num, cif, _N);
    }

    auto encd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    int_t decd;
    for (int_t i = 0; i < enc_epochs; i++)
    {
        decd = rsa_dcif(encd, dcif, _N);
    }
    auto decd_t = GET_TIME_DIFF(time, GET_CURR_TIME);

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
    printf("\ntotal_t\t\xB3%.6fms\n\n",
           float(GET_TIME_DIFF(bench_time, GET_CURR_TIME)) / 1000000);
}

void elg_bench()
{
    std::cout << "ELGAMAL CIPHER BENCHMARK" << std::endl;
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
    auto time = GET_CURR_TIME;
    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_make_private_key(&key_x, p);
    }
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_make_public_key(&key_y, &key_g, key_x, p);
    }
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    for (int_t i = 0; i < cif_iter; i++)
    {
        elg_cif(&a, &b, m, key_y, key_g, p);
    }
    auto cif_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    for (int_t i = 0; i < dcif_iter; i++)
    {
        decd = elg_dcif(a, b, key_x, p);
    }
    auto decd_t = GET_TIME_DIFF(time, GET_CURR_TIME);
    auto total_t = GET_TIME_DIFF(total_start, GET_CURR_TIME);

    printf("p\t\xB3");
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
    printf("\ntotal_t\t\xB3%.6fms\n\n",
           float(total_t) / 1000000);
}

void elgsig_bench()
{
    std::cout << "ELGAMAL SIGNATURE BENCHMARK" << std::endl;
    srand(time(0));

    int pr_k_iter = 20000000;
    int pu_k_iter = 2000;
    int sig_iter = 20000;

    int_t p = 503;
    int_t m = 20;

    assert(is_prime(p) && "p must be prime");

    int_t key_x, key_y, key_g, a, b;
    auto total_start = GET_CURR_TIME;
    auto time = GET_CURR_TIME;
    for (int_t i = 0; i < pr_k_iter; i++)
    {
        elg_make_private_key(&key_x, p);
    }
    auto pr_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    for (int_t i = 0; i < pu_k_iter; i++)
    {
        elg_make_public_key(&key_y, &key_g, key_x, p);
    }
    auto pu_k_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    time = GET_CURR_TIME;
    for (int_t i = 0; i < sig_iter; i++)
    {
        elgsig_make_signature(&a, &b, key_x, key_g, p, m);
    }
    auto sig_time = GET_TIME_DIFF(time, GET_CURR_TIME);
    auto total_t = GET_TIME_DIFF(total_start, GET_CURR_TIME);

    printf("p\t\xB3");
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
    printf("\ncheck\t\xB3");
    std::cout << elgsig_check_sig(key_y, key_g, a, b, p, m) << std::endl;
    printf("\ntotal_t\t\xB3%.6fms\n\n",
           float(total_t) / 1000000);
}

int main()
{
    rsa_bench();
    elg_bench();
    elgsig_bench();
    return 0;
}