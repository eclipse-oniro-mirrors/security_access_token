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

#include "token_sync_kit.h"

#include <string>
#include <vector>

#include "accesstoken_log.h"
#include "constant_common.h"
#include "token_sync_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncKit"};
} // namespace

int TokenSyncKit::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID=%{public}s tokenID=%{public}d",
        __func__, ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
    return TokenSyncManagerClient::GetInstance().GetRemoteHapTokenInfo(deviceID, tokenID);
}

int TokenSyncKit::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID=%{public}d", __func__, tokenID);
    return TokenSyncManagerClient::GetInstance().DeleteRemoteHapTokenInfo(tokenID);
}

int TokenSyncKit::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called tokenID=%{public}d", __func__, tokenInfo.baseInfo.tokenID);
    return TokenSyncManagerClient::GetInstance().UpdateRemoteHapTokenInfo(tokenInfo);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
