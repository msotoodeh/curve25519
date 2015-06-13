#ifndef __ecc25519_donna_h__
#define __ecc25519_donna_h__

#ifdef __cplusplus
extern "C" {
#endif

#include "BaseTypes.h"

typedef unsigned char u8;
typedef S64 felem;

void curve25519_donna(u8 *donna_publickey, const u8 *secret, const u8 *basepoint);

#ifdef __cplusplus
}
#endif
#endif  /* __ecc25519_donna_h__ */