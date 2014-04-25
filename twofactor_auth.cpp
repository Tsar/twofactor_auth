#include "twofactor_auth.h"

#include <syslog.h>
#include <security/pam_ext.h>

#include <fstream>
#include <boost/unordered_map.hpp>

typedef boost::unordered_map<std::string, std::string> U2SN_MAP_TYPE;

bool isThereDeviceWithSerial(std::string const& sn, std::string& dev) {
    // TODO: implement this function

    return false;
}

bool loadUserToSNMap(U2SN_MAP_TYPE& u2sn) {
    std::ifstream f("/etc/u2sn");
    if (!f.good())
        return false;
    std::string u, sn;
    while (f.good()) {
        f >> u >> sn;
        u2sn.insert(std::make_pair(u, sn));
    }
    f.close();
    return true;
}

int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    const char* user;
    int res = pam_get_user(pamh, &user, 0);
    if (res != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_get_user() failed: %s", pam_strerror(pamh, res));
        return PAM_USER_UNKNOWN;
    }

    U2SN_MAP_TYPE u2sn;
    if (!loadUserToSNMap(u2sn)) {
        pam_syslog(pamh, LOG_ERR, "load user-to-serial-number map failed");
        return PAM_AUTHINFO_UNAVAIL;
    }

    U2SN_MAP_TYPE::const_iterator it = u2sn.find(user);
    if (it == u2sn.end()) {
        pam_syslog(pamh, LOG_ERR, "no user '%s' in user-to-serial-number map", user);
        return PAM_USER_UNKNOWN;
    }

    std::string sn = it->second;
    std::string dev;
    if (!isThereDeviceWithSerial(sn, dev)) {
        pam_syslog(pamh, LOG_ERR, "no device with serial number '%s' is connected", sn.c_str());
        return PAM_CRED_INSUFFICIENT;
    }

    // TODO: everything else

    //pam_get_authtok()

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
