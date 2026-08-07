#include "HYUVPNKeychainAccessShim.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus HYUVPNCreateCredentialAccess(SecAccessRef _Nullable * _Nonnull accessOut) {
    if (accessOut == NULL) { return errSecParam; }
    *accessOut = NULL;

    SecTrustedApplicationRef currentApplication = NULL;
    SecTrustedApplicationRef securityTool = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &currentApplication);
    if (status != errSecSuccess) { return status; }

    status = SecTrustedApplicationCreateFromPath("/usr/bin/security", &securityTool);
    if (status != errSecSuccess) {
        if (currentApplication != NULL) { CFRelease(currentApplication); }
        return status;
    }

    const void *trustedApplications[2] = { currentApplication, securityTool };
    CFArrayRef trustedList = CFArrayCreate(kCFAllocatorDefault, trustedApplications, 2, &kCFTypeArrayCallBacks);
    if (trustedList == NULL) {
        CFRelease(currentApplication);
        CFRelease(securityTool);
        return errSecAllocate;
    }

    status = SecAccessCreate(CFSTR("HYU VPN credential access"), trustedList, accessOut);

    CFRelease(trustedList);
    CFRelease(currentApplication);
    CFRelease(securityTool);
    return status;
}

#pragma clang diagnostic pop
