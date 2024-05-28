/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EL5_FILEKEY_MANAGER_SERVICE_H
#define EL5_FILEKEY_MANAGER_SERVICE_H

#include <singleton.h>
#include "nocopyable.h"

#include "accesstoken_kit.h"
#ifdef COMMON_EVENT_SERVICE_ENABLE
#include "el5_filkey_manager_subscriber.h"
#endif
#include "el5_filekey_manager_stub.h"
#include "el5_filekey_service_ext_interface.h"
#ifdef EVENTHANDLER_ENABLE
#include "event_handler.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

class El5FilekeyManagerService : public El5FilekeyManagerStub {
public:
    El5FilekeyManagerService();
    virtual ~El5FilekeyManagerService();

    int32_t Init();

    int32_t AcquireAccess(DataLockType type) override;
    int32_t ReleaseAccess(DataLockType type) override;
    int32_t GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId) override;
    int32_t DeleteAppKey(const std::string& keyId) override;
    int32_t GetUserAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos) override;
    int32_t ChangeUserAppkeysLoadInfo(int32_t userId, std::vector<std::pair<std::string, bool>> &loadInfos) override;
    int32_t SetFilePathPolicy() override;
    
    int32_t SetPolicyScreenLocked();
    void PostDelayedUnloadTask(uint32_t delayedTime);
    void CancelDelayedUnloadTask();

private:
    ServiceRunningState serviceRunningState_ = ServiceRunningState::STATE_NOT_START;

    bool IsSystemApp();
    int32_t CheckReqLockPermission(DataLockType type, bool& isApp);
    bool VerifyNativeCallingProcess(const std::string &validCaller, const AccessTokenID &callerTokenId);
    bool VerifyHapCallingProcess(int32_t userId, const std::string &validCaller, const AccessTokenID &callerTokenId);

    El5FilekeyServiceExtInterface* service_ = nullptr;
#ifdef COMMON_EVENT_SERVICE_ENABLE
    std::shared_ptr<El5FilekeyManagerSubscriber> subscriber_;
#endif
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventHandler> unloadHandler_;
#endif

    DISALLOW_COPY_AND_MOVE(El5FilekeyManagerService);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // EL5_FILEKEY_MANAGER_SERVICE_H
