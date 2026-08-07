#ifndef HYU_VPN_KEYCHAIN_ACCESS_SHIM_H
#define HYU_VPN_KEYCHAIN_ACCESS_SHIM_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

OSStatus HYUVPNCreateCredentialAccess(SecAccessRef _Nullable * _Nonnull accessOut);

#endif
