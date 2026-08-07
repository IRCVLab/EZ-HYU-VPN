#include "HYUVPNKeychainAccessShim.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus HYUVPNCreateCredentialAccess(SecAccessRef _Nullable * _Nonnull accessOut) {
    return HYUVPNCreateCredentialAccessWithPath(NULL, accessOut);
}

OSStatus HYUVPNCreateCredentialAccessWithPath(const char * _Nullable extraTrustedPath, SecAccessRef _Nullable * _Nonnull accessOut) {
    if (accessOut == NULL) { return errSecParam; }
    *accessOut = NULL;

    SecTrustedApplicationRef currentApplication = NULL;
    SecTrustedApplicationRef securityTool = NULL;
    SecTrustedApplicationRef extraApplication = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &currentApplication);
    if (status != errSecSuccess) { return status; }

    status = SecTrustedApplicationCreateFromPath("/usr/bin/security", &securityTool);
    if (status != errSecSuccess) {
        if (currentApplication != NULL) { CFRelease(currentApplication); }
        return status;
    }

    const void *trustedApplications[3] = { currentApplication, securityTool, NULL };
    CFIndex trustedCount = 2;
    if (extraTrustedPath != NULL && extraTrustedPath[0] != '\0') {
        status = SecTrustedApplicationCreateFromPath(extraTrustedPath, &extraApplication);
        if (status != errSecSuccess) {
            CFRelease(currentApplication);
            CFRelease(securityTool);
            return status;
        }
        trustedApplications[trustedCount++] = extraApplication;
    }
    CFArrayRef trustedList = CFArrayCreate(kCFAllocatorDefault, trustedApplications, trustedCount, &kCFTypeArrayCallBacks);
    if (trustedList == NULL) {
        CFRelease(currentApplication);
        CFRelease(securityTool);
        if (extraApplication != NULL) { CFRelease(extraApplication); }
        return errSecAllocate;
    }

    status = SecAccessCreate(CFSTR("HYU VPN credential access"), trustedList, accessOut);

    CFRelease(trustedList);
    CFRelease(currentApplication);
    CFRelease(securityTool);
    if (extraApplication != NULL) { CFRelease(extraApplication); }
    return status;
}

#pragma clang diagnostic pop
