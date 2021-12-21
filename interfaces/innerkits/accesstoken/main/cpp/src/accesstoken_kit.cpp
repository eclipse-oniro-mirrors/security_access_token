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

#include "accesstoken_kit.h"

#include <string>
#include <vector>

#include "accesstoken_log.h"
#include "accesstoken_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKit"};
} // namespace

int AccessTokenKit::VerifyAccesstoken(AccessTokenID tokenID, const std::string &permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, permissionName=%{public}s",
        tokenID, permissionName.c_str());
    return AccessTokenManagerClient::GetInstance().VerifyAccesstoken(tokenID, permissionName);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS