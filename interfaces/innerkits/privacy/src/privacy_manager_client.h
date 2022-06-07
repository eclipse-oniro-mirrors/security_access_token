#ifndef PRIVACY_MANAGER_CLIENT_H
#define PRIVACY_MANAGER_CLIENT_H

#include <mutex>
#include <string>
#include <vector>

#include "i_privacy_manager.h"
#include "privacy_death_recipient.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerClient final {
public:
    static PrivacyManagerClient& GetInstance();

    virtual ~PrivacyManagerClient();

    int AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName, int successCount, int failCount);
    int StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName);
    int RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID);
    int GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result);
    int GetPermissionUsedRecords(const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback);
    std::string DumpRecordInfo(const std::string& bundleName, const std::string& permissionName);

    void OnRemoteDiedHandle();
private:
    PrivacyManagerClient();

    DISALLOW_COPY_AND_MOVE(PrivacyManagerClient);
    std::mutex proxyMutex_;
    sptr<IPrivacyManager> proxy_ = nullptr;
    sptr<PrivacyDeathRecipient> serviceDeathObserver_ = nullptr;
    void InitProxy();
    sptr<IPrivacyManager> GetProxy();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_CLIENT_H
