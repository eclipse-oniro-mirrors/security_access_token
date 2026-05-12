/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "permission_change_notifier.h"

#include <algorithm>
#include <cstdlib>
#include <mutex>

#include "accesstoken_common_log.h"
#include "callback_manager.h"
#include "constant_common.h"
#include "parameter.h"
#include "permission_map.h"
#include "permission_state_change_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static const char* PERMISSION_STATUS_FLAG_CHANGE_KEY = "accesstoken.permission.flagchange";
static constexpr int32_t VALUE_MAX_LEN = 32;
}

PermissionChangeNotifier& PermissionChangeNotifier::GetInstance()
{
    static PermissionChangeNotifier instance;
    return instance;
}

PermissionChangeNotifier::PermissionChangeNotifier()
{
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(PERMISSION_STATUS_CHANGE_KEY, "", value, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Return default value, ret=%{public}d", ret);
        paramValue_ = 0;
    } else {
        paramValue_ = static_cast<uint64_t>(std::atoll(value));
    }

    char flagValue[VALUE_MAX_LEN] = {0};
    ret = GetParameter(PERMISSION_STATUS_FLAG_CHANGE_KEY, "", flagValue, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Return default flag value, ret=%{public}d", ret);
        paramFlagValue_ = 0;
        return;
    }
    paramFlagValue_ = static_cast<uint64_t>(std::atoll(flagValue));
}

void PermissionChangeNotifier::ParamUpdate(const std::string& permissionName, uint32_t flag, bool filtered)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->permParamSetLock_);
    if (filtered || (IsOperablePermission(permissionName) &&
        ((flag != PERMISSION_PRE_AUTHORIZED_CANCELABLE) && (flag != PERMISSION_SYSTEM_FIXED)))) {
        paramValue_++;
        LOGD(ATM_DOMAIN, ATM_TAG, "paramValue_ change %{public}llu",
            static_cast<unsigned long long>(paramValue_));
        int32_t res = SetParameter(PERMISSION_STATUS_CHANGE_KEY, std::to_string(paramValue_).c_str());
        if (res != 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter failed %{public}d", res);
        }
    }
}

void PermissionChangeNotifier::ParamFlagUpdate()
{
    std::unique_lock<std::shared_mutex> infoGuard(this->permFlagParamSetLock_);
    paramFlagValue_++;
    LOGD(ATM_DOMAIN, ATM_TAG, "paramFlagValue_ change %{public}llu",
        static_cast<unsigned long long>(paramFlagValue_));
    int32_t res = SetParameter(PERMISSION_STATUS_FLAG_CHANGE_KEY, std::to_string(paramFlagValue_).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter failed %{public}d", res);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
