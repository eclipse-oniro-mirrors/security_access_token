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

#include "application_status_change_callback.h"
#include "accesstoken_log.h"
#include "sensitive_resource_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "ApplicationStatusChangeCallback"
};
}

void ApplicationStatusChangeCallback::OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(bundleName=%{public}s, uid=%{public}d, state=%{public}d)",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.state);

    uint32_t tokenId = appStateData.accessTokenId;

    if (callback_ != nullptr) {
        callback_(tokenId, appStateData.state);
    }
}

void ApplicationStatusChangeCallback::SetCallback(OnAppStatusChangeCallback callback)
{
    callback_ = callback;
}

OnAppStatusChangeCallback ApplicationStatusChangeCallback::GetCallback() const
{
    return callback_;
}

void ApplicationStatusChangeCallback::AddTokenId(uint32_t tokenId)
{
    if (std::find(tokenIdList_.begin(), tokenIdList_.end(), tokenId) == tokenIdList_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "AddTokenId, tokenId=%{public}d", tokenId);
        tokenIdList_.emplace_back(tokenId);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "AddTokenId, tokenId(%{public}d) is already exist", tokenId);
    }
}

void ApplicationStatusChangeCallback::RemoveTokenId(uint32_t tokenId)
{
    auto iter = std::find(tokenIdList_.begin(), tokenIdList_.end(), tokenId);
    if (iter != tokenIdList_.end()) {
        tokenIdList_.erase(iter);
        ACCESSTOKEN_LOG_INFO(LABEL, "RemoveTokenId, tokenId=%{public}d", tokenId);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "RemoveTokenId, tokenId(%{public}d) is not exist", tokenId);
    }
}

bool ApplicationStatusChangeCallback::IsHasListener() const
{
    return !tokenIdList_.empty();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS