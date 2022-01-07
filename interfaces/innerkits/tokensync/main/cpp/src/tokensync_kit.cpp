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

#include "tokensync_kit.h"

#include <string>
#include <vector>

#include "accesstoken_log.h"
#include "tokensync_manager_client.h"

namespace OHOS {
namespace Security {
namespace TokenSync {
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncKit"};
} // namespace

int TokenSyncKit::VerifyPermission(const string& bundleName, const string& permissionName, int userId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName=%{public}s, permissionName=%{public}s, userId=%{public}d",
        bundleName.c_str(), permissionName.c_str(), userId);
    return TokenSyncManagerClient::GetInstance().VerifyPermission(bundleName, permissionName, userId);
}
} // namespace TokenSync
} // namespace Security
} // namespace OHOS
