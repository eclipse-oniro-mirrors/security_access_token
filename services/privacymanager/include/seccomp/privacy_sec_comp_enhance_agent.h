/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef PERMISSION_SEC_COMP_ENHANCE_AGENT_H
#define PERMISSION_SEC_COMP_ENHANCE_AGENT_H

#include <mutex>
#include <vector>
#include "app_manager_death_callback.h"
#include "app_status_change_callback.h"
#include "nocopyable.h"
#include "sec_comp_enhance_data.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyAppUsingSecCompStateObserver : public ApplicationStateObserverStub {
public:
    PrivacyAppUsingSecCompStateObserver() = default;
    ~PrivacyAppUsingSecCompStateObserver() = default;

    void OnProcessDied(const ProcessData &processData) override;
    DISALLOW_COPY_AND_MOVE(PrivacyAppUsingSecCompStateObserver);
};

class PrivacySecCompAppManagerDeathCallback : public AppManagerDeathCallback {
public:
    PrivacySecCompAppManagerDeathCallback() = default;
    ~PrivacySecCompAppManagerDeathCallback() = default;

    void NotifyAppManagerDeath() override;
    DISALLOW_COPY_AND_MOVE(PrivacySecCompAppManagerDeathCallback);
};

class PrivacySecCompEnhanceAgent final {
public:
    static PrivacySecCompEnhanceAgent& GetInstance();
    virtual ~PrivacySecCompEnhanceAgent();

    int32_t RegisterSecCompEnhance(const SecCompEnhanceData& enhanceData);
    int32_t UpdateSecCompEnhance(int32_t pid, int32_t seqNum);
    int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhanceData);
    int32_t GetSpecialSecCompEnhance(const std::string& bundleName,
        std::vector<SecCompEnhanceData>& enhanceList);
    void RemoveSecCompEnhance(int pid);
    void OnAppMgrRemoteDiedHandle();

private:
    PrivacySecCompEnhanceAgent();
    void InitAppObserver();
    DISALLOW_COPY_AND_MOVE(PrivacySecCompEnhanceAgent);

private:
    sptr<PrivacyAppUsingSecCompStateObserver> observer_ = nullptr;
    std::shared_ptr<PrivacySecCompAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;
    std::mutex secCompEnhanceMutex_;
    std::vector<SecCompEnhanceData> secCompEnhanceData_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_SEC_COMP_ENHANCE_AGENT_H
