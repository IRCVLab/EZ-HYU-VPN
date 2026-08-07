#include "HYUVPNKeychainAccessShim.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus HYUVPNCreateCredentialAccess(SecAccessRef _Nullable * _Nonnull accessOut) {
    return HYUVPNCreateCredentialAccessWithPaths(NULL, NULL, accessOut);
}

OSStatus HYUVPNCreateCredentialAccessWithPath(const char * _Nullable extraTrustedPath, SecAccessRef _Nullable * _Nonnull accessOut) {
    return HYUVPNCreateCredentialAccessWithPaths(extraTrustedPath, NULL, accessOut);
}

OSStatus HYUVPNCreateCredentialAccessWithPaths(const char * _Nullable firstTrustedPath, const char * _Nullable secondTrustedPath, SecAccessRef _Nullable * _Nonnull accessOut) {
    if (accessOut == NULL) { return errSecParam; }
    *accessOut = NULL;

    SecTrustedApplicationRef currentApplication = NULL;
    SecTrustedApplicationRef firstApplication = NULL;
    SecTrustedApplicationRef secondApplication = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &currentApplication);
    if (status != errSecSuccess) { return status; }

    const void *trustedApplications[3] = { currentApplication, NULL, NULL };
    CFIndex trustedCount = 1;
    if (firstTrustedPath != NULL && firstTrustedPath[0] != '\0') {
        status = SecTrustedApplicationCreateFromPath(firstTrustedPath, &firstApplication);
        if (status != errSecSuccess) {
            CFRelease(currentApplication);
            return status;
        }
        trustedApplications[trustedCount++] = firstApplication;
    }
    if (secondTrustedPath != NULL && secondTrustedPath[0] != '\0') {
        status = SecTrustedApplicationCreateFromPath(secondTrustedPath, &secondApplication);
        if (status != errSecSuccess) {
            CFRelease(currentApplication);
            if (firstApplication != NULL) { CFRelease(firstApplication); }
            return status;
        }
        trustedApplications[trustedCount++] = secondApplication;
    }
    CFArrayRef trustedList = CFArrayCreate(kCFAllocatorDefault, trustedApplications, trustedCount, &kCFTypeArrayCallBacks);
    if (trustedList == NULL) {
        CFRelease(currentApplication);
        if (firstApplication != NULL) { CFRelease(firstApplication); }
        if (secondApplication != NULL) { CFRelease(secondApplication); }
        return errSecAllocate;
    }

    status = SecAccessCreate(CFSTR("HYU VPN credential access"), trustedList, accessOut);

    CFRelease(trustedList);
    CFRelease(currentApplication);
    if (firstApplication != NULL) { CFRelease(firstApplication); }
    if (secondApplication != NULL) { CFRelease(secondApplication); }
    return status;
}

#pragma clang diagnostic pop
