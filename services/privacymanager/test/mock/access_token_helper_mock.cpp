/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "access_token_helper.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t NATIVE_WITH_PERM = 672000000;
std::string BACKGROUND_MIC_PERM = "ohos.permission.MICROPHONE_BACKGROUND";
std::string BACKGROUND_CAM_PERM = "ohos.permission.CAMERA_BACKGROUND";
}
int32_t AccessTokenHelper::VerifyAccessToken(const AccessTokenID& callerToken,
    const std::string& permission)
{
    if (AccessTokenKit::GetTokenTypeFlag(callerToken) == TOKEN_NATIVE &&
        (permission == BACKGROUND_MIC_PERM || permission == BACKGROUND_CAM_PERM)) {
        if (callerToken > NATIVE_WITH_PERM) {
            return PERMISSION_GRANTED;
        }
        return PERMISSION_DENIED;
    }
    return AccessTokenKit::VerifyAccessToken(callerToken, permission);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS