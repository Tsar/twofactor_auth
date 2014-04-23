#include "twofactor_auth.h"

#include <syslog.h>
#include <security/pam_ext.h>

int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    const char* user;
    int res = pam_get_user(pamh, &user, 0);
    if (res != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_get_user() failed: %s", pam_strerror(pamh, res));
        return PAM_USER_UNKNOWN;
    }

    return PAM_SUCCESS;
}
