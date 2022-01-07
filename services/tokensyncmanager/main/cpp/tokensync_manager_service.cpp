/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "tokensync_manager_service.h"

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace TokenSync {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerService"};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());

TokenSyncManagerService::TokenSyncManagerService()
    : SystemAbility(SA_ID_TOKENSYNC_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService()");
}

TokenSyncManagerService::~TokenSyncManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~TokenSyncManagerService()");
}

void TokenSyncManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService has already started!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenSyncManagerService is starting");
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<TokenSyncManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, TokenSyncManagerService start successfully!");
}

void TokenSyncManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int TokenSyncManagerService::VerifyPermission(
    const std::string& bundleName, const std::string& permissionName, int userId)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, packageName: %{public}s, permissionName: %{public}s, userId: %{public}d", __func__,
        bundleName.c_str(), permissionName.c_str(), userId);
    return 0;
}

bool TokenSyncManagerService::Initialize() const
{
    return true;
}
} // namespace TokenSync
} // namespace Security
}
