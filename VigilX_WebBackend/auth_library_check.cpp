#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
int main() { unsigned char b[16]; return RAND_bytes(b, sizeof(b)) != 1; }
