#include "pam_twofactor_auth.h"

#include <syslog.h>
//#include <security/pam_ext.h>

#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <set>
#include <map>

namespace {

typedef std::map<std::string, std::string> U2SN_MAP_TYPE;

bool startsWith(const std::string& str, const std::string& tmpl) {
    return str.length() >= tmpl.length() && str.substr(0, tmpl.length()) == tmpl;
}

int getDeviceBySerialNumber(std::string const& sn, std::string& device) {
    std::string path("/dev/disk/by-id");
    DIR* dirp = opendir(path.c_str());
    if (dirp == 0)
        return PAM_AUTHINFO_UNAVAIL;

    dirent* dp;
    std::string ans = "";
    while ((dp = readdir(dirp)) != NULL) {
        std::string str(dp->d_name);
        if (startsWith(str, "usb") && str.find(sn) != std::string::npos) {
            char buf[256];
            int len = readlink((path + "/" + str).c_str(), buf, 256);
            buf[len] = 0;
            realpath((path + "/" + buf).c_str(), buf);
            ans = std::string(buf);
            if (!(ans[ans.length() - 1] >= '0' && ans[ans.length() - 1] <= '9')) {
                break;
            }
        }
    }
    closedir(dirp);
    if (ans.length() == 0)
        return PAM_CRED_INSUFFICIENT;

    device = ans;
    return PAM_SUCCESS;
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

bool pamConvConv1(pam_handle_t* pamh, int msgStyle, std::string const& message, std::string* response);

void errorMessage(pam_handle_t* pamh, std::string const& errMsg, bool toPAMConv = true) {
    //pam_syslog(pamh, LOG_ERR, "%s", errMsg.c_str());
    if (toPAMConv) {
        pamConvConv1(pamh, PAM_ERROR_MSG, "ptfa: " + errMsg, 0);
    } else {
        std::cerr << "pam_twofactor_auth: " << errMsg << std::endl;
    }
}

bool pamConvConv1(pam_handle_t* pamh, int msgStyle, std::string const& message, std::string* response) {
    pam_conv* conv;

    int res = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (res != PAM_SUCCESS) {
        errorMessage(pamh, std::string("pam_get_item() failed: ") + pam_strerror(pamh, res), false);
        return false;
    }
    if (conv == 0 || conv->conv == 0) {
        errorMessage(pamh, "'conv' or 'conv->conv' is zero-pointer", false);
        return false;
    }

    pam_response* resp;
    pam_message* msg = new pam_message[1];
    msg[0].msg_style = msgStyle;
    msg[0].msg = message.c_str();

    res = conv->conv(1, (const pam_message**)&msg, &resp, conv->appdata_ptr);
    delete[] msg;
    if (res != PAM_SUCCESS) {
        errorMessage(pamh, std::string("conv->conv failed: ") + pam_strerror(pamh, res), false);
        return false;
    }
    if (response && (resp == 0 || resp[0].resp == 0)) {
        errorMessage(pamh, "'resp' or 'resp[0].resp' is zero-pointer", false);
        return false;
    }

    if (response)
        *response = resp[0].resp;
    if (resp)
        free(&resp[0]);

    return true;
}

bool askForPassword(pam_handle_t* pamh, std::string& password) {
    return pamConvConv1(pamh, PAM_PROMPT_ECHO_OFF, "Password for 'ptfa.key': ", &password);
}

}

int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    //return PAM_SUCCESS;

    const char* user;
    int res = pam_get_user(pamh, &user, 0);
    if (res != PAM_SUCCESS) {
        errorMessage(pamh, std::string("pam_get_user() failed: ") + pam_strerror(pamh, res));
        return PAM_USER_UNKNOWN;
    }

    U2SN_MAP_TYPE u2sn;
    if (!loadUserToSNMap(u2sn)) {
        errorMessage(pamh, "Load of user-to-serial-number map failed");
        return PAM_AUTHINFO_UNAVAIL;
    }

    U2SN_MAP_TYPE::const_iterator it = u2sn.find(user);
    if (it == u2sn.end()) {
        errorMessage(pamh, std::string("No user '") + user + "' in user-to-serial-number map");
        return PAM_USER_UNKNOWN;
    }

    std::string sn = it->second;
    std::string dev;
    res = getDeviceBySerialNumber(sn, dev);
    if (res == PAM_CRED_INSUFFICIENT) {
        errorMessage(pamh, "No device with serial number '" + sn + "' is connected");
        return PAM_CRED_INSUFFICIENT;
    } else if (res != PAM_SUCCESS) {
        errorMessage(pamh, "Kernel is incompatible with pam_twofactor_auth module ('/dev/disk/by-id' directory should be present)");
        return PAM_AUTHINFO_UNAVAIL;
    }

    std::set<std::string> usbPartitions;
    DIR* devDir;
    if ((devDir = opendir("/dev/")) != 0) {
        dirent* devDirEntry;
        while ((devDirEntry = readdir(devDir)) != 0) {
            std::string fileName = std::string("/dev/") + devDirEntry->d_name;
            if (fileName.length() > dev.length() && startsWith(fileName, dev)) {
                usbPartitions.insert(fileName);
            }
        }
        closedir(devDir);
    } else {
        errorMessage(pamh, "Error while trying to access '/dev' directory");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (usbPartitions.size() == 0) {
        usbPartitions.insert(dev);
    }

    bool keyFileFound = false;

    std::ifstream mtab("/etc/mtab");
    if (!mtab.good()) {
        errorMessage(pamh, "Could not open '/etc/mtab', maybe it does not exist");
        return PAM_AUTHINFO_UNAVAIL;
    }
    while (mtab.good()) {
        std::string mtabLine, mtabDev, mtabMountPoint;
        getline(mtab, mtabLine);
        std::istringstream mtabLineISS(mtabLine);
        mtabLineISS >> mtabDev >> mtabMountPoint;
        if (usbPartitions.find(mtabDev) != usbPartitions.end()) {
            usbPartitions.erase(mtabDev);
            std::string keyFileName = mtabMountPoint + "/ptfa.key";
            if (std::ifstream(keyFileName.c_str()) != 0) {
                // TODO: read the key file

                keyFileFound = true;
                break;
            }
        }
    }
    mtab.close();

    if (!keyFileFound) {
        for (std::set<std::string>::const_iterator it = usbPartitions.begin(); it != usbPartitions.end(); ++it) {
            if (system("umount /tmp/ptfa_temporary_mount_point 2> /dev/null") == 0)
                system("rm -rf /tmp/ptfa_temporary_mount_point");

            system("mkdir /tmp/ptfa_temporary_mount_point");
            std::string mountCmd = "mount " + *it + " /tmp/ptfa_temporary_mount_point";
            int mountRes = system(mountCmd.c_str());
            if (mountRes != 0)
                continue;

            if (std::ifstream("/tmp/ptfa_temporary_mount_point/ptfa.key") != 0) {
                // TODO: read the key file

                keyFileFound = true;
                break;
            }
        }

        if (system("umount /tmp/ptfa_temporary_mount_point 2> /dev/null") == 0)
            system("rm -rf /tmp/ptfa_temporary_mount_point");
    }

    if (!keyFileFound) {
        errorMessage(pamh, "No 'ptfa.key' file found on any accessible partition of '" + dev + "'");
        return PAM_CRED_INSUFFICIENT;
    }

    std::string password;
    if (!askForPassword(pamh, password)) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    /**
      TODO:
       - decrypt key using password;
       - if decryption in previous step fails, than ask for password again until decryption is done successfully or number of tries is exceeded;
     */

    // Temporary line for testing
    std::string decryptedKey = password;

    res = pam_set_item(pamh, PAM_AUTHTOK, decryptedKey.c_str());
    if (res != PAM_SUCCESS) {
        errorMessage(pamh, "Failed to set auth token to decrypted key's value");
    }

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_auth_modstruct = {
    "pam_twofactor_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
