/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "iservice_registry.h"
#include "mock_app_mgr_service.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "system_ability_manager_proxy.h"
#include "mock_test.h"

namespace OHOS {
static uint32_t g_mockFlag = 0;
static sptr<AppExecFwk::MockAppMgrService> g_appMgrService = nullptr;

void SetAppProxyFlag(uint32_t flag)
{
    g_mockFlag = flag;
}

void SwitchForeOrBackGround(uint32_t tokenId, int32_t flag)
{
    if (g_appMgrService == nullptr) {
        return;
    }
    g_appMgrService->SwitchForeOrBackGround(tokenId, flag);
}

SystemAbilityManagerClient& SystemAbilityManagerClient::GetInstance()
{
    static auto instance = new SystemAbilityManagerClient();
    return *instance;
}

sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    if (g_mockFlag == 0) {
        GTEST_LOG_(INFO) << "GetSystemAbilityManager: return nullptr";
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(systemAbilityManagerLock_);
    if (systemAbilityManager_ != nullptr) {
        return systemAbilityManager_;
    }

    systemAbilityManager_ = new SystemAbilityManagerProxy(nullptr);
    return systemAbilityManager_;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::GetSystemAbility(int32_t systemAbilityId)
{
    if (g_mockFlag == 1) {
        GTEST_LOG_(INFO) << "GetSystemAbility(" << systemAbilityId << "): return nullptr";
        return nullptr;
    }
    sptr<IRemoteObject> remote = nullptr;
    switch (systemAbilityId) {
        case APP_MGR_SERVICE_ID:
            if (!g_appMgrService) {
                GTEST_LOG_(INFO) << "GetSystemAbility(" << systemAbilityId << "): return MockAppMgrService";
                g_appMgrService = new AppExecFwk::MockAppMgrService();
            }
            remote = g_appMgrService;
            break;
        default:
            GTEST_LOG_(INFO) << "This service is not dummy!!!!" << systemAbilityId;
            break;
    }
    return remote;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::GetSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    return GetSystemAbility(systemAbilityId);
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId, bool& isExist)
{
    return nullptr;
}

int32_t SystemAbilityManagerProxy::AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
    const std::u16string& localAbilityManagerName)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::RemoveSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::RemoveSystemAbility(int32_t systemAbilityId)
{
    return -1;
}

std::vector<std::u16string> SystemAbilityManagerProxy::ListSystemAbilities(unsigned int dumpFlags)
{
    std::vector<std::u16string> saNames;

    return saNames;
}

int32_t SystemAbilityManagerProxy::SubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityStatusChange>& listener)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::UnSubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityStatusChange>& listener)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::LoadSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityLoadCallback>& callback)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::LoadSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
    const sptr<ISystemAbilityLoadCallback>& callback)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::AddSystemAbility(int32_t systemAbilityId, const sptr<IRemoteObject>& ability,
    const SAExtraProp& extraProp)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::AddSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return -1;
}

int32_t SystemAbilityManagerProxy::AddSystemProcess(
    const std::u16string& procName, const sptr<IRemoteObject>& procObject)
{
    return -1;
}
}