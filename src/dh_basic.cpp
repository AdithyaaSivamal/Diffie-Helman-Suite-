#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "util.h"

using namespace std;

int main() {
    cout << "\n========================================\n";
    cout << "    Diffie-Hellman Key Exchange (Basic)  \n";
    cout << "========================================\n\n";

    // Input public parameters
    string p_str, g_str;
    cout << "Enter prime number (p): ";
    cin >> p_str;
    cout << "Enter generator (g): ";
    cin >> g_str;

    BIGNUM *p = BN_new(), *g = BN_new();
    BN_dec2bn(&p, p_str.c_str());
    BN_dec2bn(&g, g_str.c_str());

    // Validate inputs
    if (!BN_is_prime_ex(p, 64, NULL, NULL)) {
        cout << "Error: p must be prime!\n";
        return 1;
    }
    if (BN_cmp(g, p) >= 0 || BN_is_zero(g)) {
        cout << "Error: g must be 0 < g < p!\n";
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();

    // Alice's keys
    BIGNUM *a = BN_new();  // Secret key
    BIGNUM *A = BN_new();  // Public key
    BN_rand_range(a, p);   // Random secret key < p
    BN_mod_exp(A, g, a, p, ctx);  // A = g^a mod p

    // Bob's keys
    BIGNUM *b = BN_new();  // Secret key
    BIGNUM *B = BN_new();  // Public key
    BN_rand_range(b, p);   // Random secret key < p
    BN_mod_exp(B, g, b, p, ctx);  // B = g^b mod p

    // Shared keys
    BIGNUM *shared_a = BN_new();  // Alice computes B^a mod p
    BIGNUM *shared_b = BN_new();  // Bob computes A^b mod p
    BN_mod_exp(shared_a, B, a, p, ctx);
    BN_mod_exp(shared_b, A, b, p, ctx);

    // Display results
    cout << "\nPublic Parameters:\n";
    cout << "p = " << BN_bn2dec(p) << "\n";
    cout << "g = " << BN_bn2dec(g) << "\n";

    cout << "\nAlice:\n";
    cout << "Secret key (a) = " << BN_bn2dec(a) << "\n";
    cout << "Public key (A) = " << BN_bn2dec(A) << "\n";

    cout << "\nBob:\n";
    cout << "Secret key (b) = " << BN_bn2dec(b) << "\n";
    cout << "Public key (B) = " << BN_bn2dec(B) << "\n";

    cout << "\nShared Keys:\n";
    cout << "Alice's shared key = " << BN_bn2dec(shared_a) << "\n";
    cout << "Bob's shared key = " << BN_bn2dec(shared_b) << "\n";

    // Verify
    if (BN_cmp(shared_a, shared_b) == 0) {
        cout << "\nSuccess: Shared keys match!\n";
    } else {
        cout << "\nError: Shared keys do not match!\n";
    }
    cout << "========================================\n";

    // Cleanup
    BN_free(p); BN_free(g); BN_free(a); BN_free(A);
    BN_free(b); BN_free(B); BN_free(shared_a); BN_free(shared_b);
    BN_CTX_free(ctx);

    return 0;
}
