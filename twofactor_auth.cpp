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

    // TODO: implement this function

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // TODO: implement this function

    return PAM_SUCCESS;
}


int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_PERM_DENIED;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_PERM_DENIED;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SESSION_ERR;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SESSION_ERR;
}
