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

#include "el5_filekey_manager_service_ability.h"

#include "el5_filekey_manager_error.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
REGISTER_SYSTEM_ABILITY_BY_ID(El5FilekeyManagerServiceAbility, EL5_FILEKEY_MANAGER_SERVICE_ID, false);
}

El5FilekeyManagerServiceAbility::El5FilekeyManagerServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), service_(nullptr)
{
    LOG_INFO("El5FilekeyManagerServiceAbility start.");
}

El5FilekeyManagerServiceAbility::~El5FilekeyManagerServiceAbility()
{
    LOG_INFO("El5FilekeyManagerServiceAbility stop.");
}

void El5FilekeyManagerServiceAbility::OnStart(const SystemAbilityOnDemandReason &startReason)
{
    LOG_INFO("OnStart called.");
    std::string reasonName = startReason.GetName();
    LOG_INFO("El5FilekeyManager onStart reason name:%{public}s", reasonName.c_str());

    if (service_ != nullptr) {
        LOG_ERROR("The El5FilekeyManagerService has existed.");
        return;
    }

    service_ = DelayedSingleton<El5FilekeyManagerService>::GetInstance();
    int32_t ret = service_->Init();
    if (ret != EFM_SUCCESS) {
        LOG_ERROR("Failed to init the El5FilekeyManagerService instance.");
        return;
    }

    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(SCREENLOCK_SERVICE_ID);
    AddSystemAbilityListener(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    AddSystemAbilityListener(TIME_SERVICE_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);

    if (reasonName == "usual.event.SCREEN_LOCKED") {
        service_->SetPolicyScreenLocked();
    } else if (reasonName == "usual.event.USER_REMOVED" || reasonName == "usual.event.USER_STOPPED") {
        std::string strUserId = startReason.GetValue();
        int32_t userId = 0;
        if (StrToInt(strUserId, userId)) {
            LOG_INFO("El5 manager start, common event:%{public}s userId:%{public}d", reasonName.c_str(), userId);
            service_->HandleUserCommonEvent(reasonName, userId);
        } else {
            LOG_ERROR("El5 manager start, invalid userId:%{public}s", strUserId.c_str());
        }
    }

    if (!Publish(service_.get())) {
        LOG_ERROR("Failed to publish El5FilekeyManagerService to SystemAbilityMgr");
        return;
    }
}

void El5FilekeyManagerServiceAbility::OnStop()
{
    LOG_INFO("OnStop called.");
    if (service_) {
        service_->UnInit();
        service_ = nullptr;
    }
}

void El5FilekeyManagerServiceAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (service_) {
        service_->OnAddSystemAbility(systemAbilityId, deviceId);
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
