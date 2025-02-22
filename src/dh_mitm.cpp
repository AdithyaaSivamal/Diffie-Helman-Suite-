#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "util.h"

using namespace std;

int main() {
    cout << "\n========================================\n";
    cout << "  Diffie-Hellman with MITM Attack       \n";
    cout << "========================================\n\n";

    string p_str, g_str;
    cout << "Enter prime number (p): ";
    cin >> p_str;
    cout << "Enter generator (g): ";
    cin >> g_str;

    BIGNUM *p = BN_new(), *g = BN_new();
    BN_dec2bn(&p, p_str.c_str());
    BN_dec2bn(&g, g_str.c_str());

    BN_CTX *ctx = BN_CTX_new();

    // Alice's keys
    BIGNUM *a = BN_new(), *A = BN_new();
    BN_rand_range(a, p);
    BN_mod_exp(A, g, a, p, ctx);

    // Bob's keys
    BIGNUM *b = BN_new(), *B = BN_new();
    BN_rand_range(b, p);
    BN_mod_exp(B, g, b, p, ctx);

    // Mallory's attack: generates her own keys
    BIGNUM *m1 = BN_new(), *M1 = BN_new();  // For Alice
    BIGNUM *m2 = BN_new(), *M2 = BN_new();  // For Bob
    BN_rand_range(m1, p);
    BN_rand_range(m2, p);
    BN_mod_exp(M1, g, m1, p, ctx);  // M1 = g^m1 mod p
    BN_mod_exp(M2, g, m2, p, ctx);  // M2 = g^m2 mod p

    // Shared keys with MITM
    BIGNUM *shared_a_m = BN_new();  // Alice with Mallory
    BIGNUM *shared_m_a = BN_new();  // Mallory with Alice
    BIGNUM *shared_b_m = BN_new();  // Bob with Mallory
    BIGNUM *shared_m_b = BN_new();  // Mallory with Bob
    BN_mod_exp(shared_a_m, M1, a, p, ctx);  // Alice: M1^a
    BN_mod_exp(shared_m_a, A, m1, p, ctx);  // Mallory: A^m1
    BN_mod_exp(shared_b_m, M2, b, p, ctx);  // Bob: M2^b
    BN_mod_exp(shared_m_b, B, m2, p, ctx);  // Mallory: B^m2

    // Display results
    cout << "\nAlice sends A = " << BN_bn2dec(A) << " (intercepted by Mallory)\n";
    cout << "Bob sends B = " << BN_bn2dec(B) << " (intercepted by Mallory)\n";
    cout << "Mallory sends M1 = " << BN_bn2dec(M1) << " to Alice\n";
    cout << "Mallory sends M2 = " << BN_bn2dec(M2) << " to Bob\n";

    cout << "\nShared Keys:\n";
    cout << "Alice-Mallory key = " << BN_bn2dec(shared_a_m) << "\n";
    cout << "Mallory-Alice key = " << BN_bn2dec(shared_m_a) << "\n";
    cout << "Bob-Mallory key = " << BN_bn2dec(shared_b_m) << "\n";
    cout << "Mallory-Bob key = " << BN_bn2dec(shared_m_b) << "\n";

    cout << "\nMITM Success: Mallory has separate keys with Alice and Bob!\n";
    cout << "========================================\n";

    // Cleanup
    BN_free(p); BN_free(g); BN_free(a); BN_free(A);
    BN_free(b); BN_free(B); BN_free(m1); BN_free(M1);
    BN_free(m2); BN_free(M2); BN_free(shared_a_m); BN_free(shared_m_a);
    BN_free(shared_b_m); BN_free(shared_m_b);
    BN_CTX_free(ctx);

    return 0;
}
