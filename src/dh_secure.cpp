#include <iostream>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include "util.h"

using namespace std;

BIGNUM* sign(BIGNUM* msg, BIGNUM* d, BIGNUM* n, BN_CTX* ctx) {
    BIGNUM* sig = BN_new();
    BN_mod_exp(sig, msg, d, n, ctx);
    return sig;
}

bool verify(BIGNUM* msg, BIGNUM* sig, BIGNUM* e, BIGNUM* n, BN_CTX* ctx) {
    BIGNUM* computed = BN_new();
    BN_mod_exp(computed, sig, e, n, ctx);
    bool valid = (BN_cmp(computed, msg) == 0);
    BN_free(computed);
    return valid;
}

int main() {
    cout << "\n========================================\n";
    cout << "    Diffie-Hellman (Secure with RSA)    \n";
    cout << "========================================\n\n";

    // Load RSA public keys
    vector<string> publicKeys = readLines("../data/publickey.txt", 4);
    BIGNUM *e1 = BN_new(), *n1 = BN_new(), *e2 = BN_new(), *n2 = BN_new();
    BN_dec2bn(&e1, publicKeys[0].c_str());
    BN_dec2bn(&n1, publicKeys[1].c_str());
    BN_dec2bn(&e2, publicKeys[2].c_str());
    BN_dec2bn(&n2, publicKeys[3].c_str());

    // Input private keys
    string d1_str, d2_str;
    cout << "Enter Alice's private key (d1): ";
    cin >> d1_str;
    cout << "Enter Bob's private key (d2): ";
    cin >> d2_str;
    BIGNUM *d1 = BN_new(), *d2 = BN_new();
    BN_dec2bn(&d1, d1_str.c_str());
    BN_dec2bn(&d2, d2_str.c_str());

    // DH parameters
    string p_str, g_str;
    cout << "\nEnter prime number (p): ";
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
    BIGNUM *sig_A = sign(A, d1, n1, ctx);

    // Bob's keys
    BIGNUM *b = BN_new(), *B = BN_new();
    BN_rand_range(b, p);
    BN_mod_exp(B, g, b, p, ctx);
    BIGNUM *sig_B = sign(B, d2, n2, ctx);

    // Verify signatures
    bool alice_valid = verify(B, sig_B, e2, n2, ctx);  // Alice verifies Bob's key
    bool bob_valid = verify(A, sig_A, e1, n1, ctx);    // Bob verifies Alice's key

    if (!alice_valid || !bob_valid) {
        cout << "\nSignature verification failed! Possible MITM attack.\n";
        cout << "========================================\n";
        return 1;
    }

    // Compute shared keys
    BIGNUM *shared_a = BN_new(), *shared_b = BN_new();
    BN_mod_exp(shared_a, B, a, p, ctx);
    BN_mod_exp(shared_b, A, b, p, ctx);

    // Display
    cout << "\nAlice's public key (A) = " << BN_bn2dec(A) << "\n";
    cout << "Bob's public key (B) = " << BN_bn2dec(B) << "\n";
    cout << "Shared key (Alice) = " << BN_bn2dec(shared_a) << "\n";
    cout << "Shared key (Bob) = " << BN_bn2dec(shared_b) << "\n";
    cout << "\nSuccess: Secure key exchange completed!\n";
    cout << "========================================\n";

    // Cleanup
    BN_free(p); BN_free(g); BN_free(a); BN_free(A); BN_free(sig_A);
    BN_free(b); BN_free(B); BN_free(sig_B); BN_free(shared_a); BN_free(shared_b);
    BN_free(e1); BN_free(n1); BN_free(e2); BN_free(n2); BN_free(d1); BN_free(d2);
    BN_CTX_free(ctx);

    return 0;
}
