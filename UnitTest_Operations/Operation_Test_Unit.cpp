#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <pbc/pbc.h>

using namespace std;
using namespace std::chrono;

int main()
{
    const int TEST_NUM = 1000;

    // ------------------------------------------------------------------
    // Load pairing parameters
    // ------------------------------------------------------------------
    pairing_t pairing;

    const string param_file = "./Param/a.param";

    char param[10240];

    ifstream file(param_file, ios::binary);
    if (!file)
    {
        cerr << "Cannot open parameter file." << endl;
        return -1;
    }

    file.read(param, sizeof(param));
    size_t count = file.gcount();

    pairing_init_set_buf(pairing, param, count);

    // ------------------------------------------------------------------
    // Initialize elements
    // ------------------------------------------------------------------

    element_t g, h, gt;
    element_t x;

    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_GT(gt, pairing);
    element_init_Zr(x, pairing);

    element_random(g);
    element_random(h);
    element_random(x);

    // ------------------------------------------------------------------
    // 1. Hash Benchmark
    // ------------------------------------------------------------------

    element_t hash_elem;
    element_init_G1(hash_elem, pairing);

    const char msg[] = "Hello PBC Benchmark";

    auto hash_start = high_resolution_clock::now();

    for (int i = 0; i < TEST_NUM; i++)
    {
        element_from_hash(hash_elem, (void *)msg, strlen(msg));
    }

    auto hash_end = high_resolution_clock::now();

    double hash_avg =
        duration_cast<nanoseconds>(hash_end - hash_start).count()
        / (double)TEST_NUM;

    // ------------------------------------------------------------------
    // 2. Exponentiation Benchmark
    // ------------------------------------------------------------------

    element_t exp_result;
    element_init_G1(exp_result, pairing);

    auto exp_start = high_resolution_clock::now();

    for (int i = 0; i < TEST_NUM; i++)
    {
        element_pow_zn(exp_result, g, x);
    }

    auto exp_end = high_resolution_clock::now();

    double exp_avg =
        duration_cast<nanoseconds>(exp_end - exp_start).count()
        / (double)TEST_NUM;

    // ------------------------------------------------------------------
    // 3. Pairing Benchmark
    // ------------------------------------------------------------------

    auto pair_start = high_resolution_clock::now();

    for (int i = 0; i < TEST_NUM; i++)
    {
        pairing_apply(gt, g, h, pairing);
    }

    auto pair_end = high_resolution_clock::now();

    double pair_avg =
        duration_cast<nanoseconds>(pair_end - pair_start).count()
        / (double)TEST_NUM;

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    cout << "======================================" << endl;
    cout << "Benchmark Results (" << TEST_NUM << " runs)" << endl;
    cout << "======================================" << endl;

    cout << "Hash      : "
         << hash_avg / 1000.0
         << " us" << endl;

    cout << "Exponent  : "
         << exp_avg / 1000.0
         << " us" << endl;

    cout << "Pairing   : "
         << pair_avg / 1000.0
         << " us" << endl;

    // ------------------------------------------------------------------
    // Clear
    // ------------------------------------------------------------------

    element_clear(g);
    element_clear(h);
    element_clear(gt);
    element_clear(x);
    element_clear(hash_elem);
    element_clear(exp_result);

    pairing_clear(pairing);

    return 0;
}