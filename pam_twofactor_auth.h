#ifndef PAM_TWOFACTOR_AUTH
#define PAM_TWOFACTOR_AUTH

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>

extern "C" {

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);

}

#endif
