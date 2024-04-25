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

void El5FilekeyManagerServiceAbility::OnStart()
{
    LOG_INFO("OnStart called.");
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

    if (!Publish(service_.get())) {
        LOG_ERROR("Failed to publish El5FilekeyManagerService to SystemAbilityMgr");
        return;
    }
}

void El5FilekeyManagerServiceAbility::OnStop()
{
    LOG_INFO("onStop called.");
    service_ = nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
