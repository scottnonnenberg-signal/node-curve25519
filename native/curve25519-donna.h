
#ifndef __CURVE_DONNA_H__
#define __CURVE_DONNA_H__

#ifdef __cplusplus
extern "C" {
#endif

int curve25519_donna(unsigned char* curve25519_key_out,
                     unsigned char* curve25519_privkey_in,
                     unsigned char* curve25519_basepoint_in);

#ifdef __cplusplus
}
#endif

#endif
