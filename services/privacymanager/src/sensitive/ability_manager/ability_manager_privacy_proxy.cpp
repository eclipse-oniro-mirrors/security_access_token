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

#include "ability_manager_privacy_proxy.h"
#include "accesstoken_log.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AbilityManagerPrivacyProxy"};
}

int AbilityManagerPrivacyProxy::StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
    int requestCode, int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&want)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "want write failed.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (callerToken) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(callerToken)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "callerToken and flag write failed.");
            return PrivacyError::ERR_WRITE_PARCEL_FAILED;
        }
    } else {
        if (!data.WriteBool(false)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "flag write failed.");
            return PrivacyError::ERR_WRITE_PARCEL_FAILED;
        }
    }
    if (!data.WriteInt32(userId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "userId write failed.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(requestCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "requestCode write failed.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    int error = Remote()->SendRequest(
        static_cast<uint32_t>(IAbilityManager::AbilityManagerMessage::START_ABILITY_ADD_CALLER), data, reply, option);
    if (error != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
