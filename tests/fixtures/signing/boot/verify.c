#include <openssl/rsa.h>
static const unsigned char ROOT_PUBKEY[] = { 0x30, 0x82, 0x01, 0xa2 };
int verify_image(const unsigned char *img, size_t n, const unsigned char *sig) {
    RSA *rsa = load_root(ROOT_PUBKEY);
    return RSA_verify(NID_sha256, img, n, sig, 384, rsa);
}
