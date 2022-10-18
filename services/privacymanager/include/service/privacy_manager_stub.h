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

#ifndef PRIVACY_MANAGER_STUB_H
#define PRIVACY_MANAGER_STUB_H

#include "i_privacy_manager.h"

#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerStub : public IRemoteStub<IPrivacyManager> {
public:
    PrivacyManagerStub() = default;
    virtual ~PrivacyManagerStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    void AddPermissionUsedRecordInner(MessageParcel& data, MessageParcel& reply);
    void StartUsingPermissionInner(MessageParcel& data, MessageParcel& reply);
    void StartUsingPermissionCallbackInner(MessageParcel& data, MessageParcel& reply);
    void StopUsingPermissionInner(MessageParcel& data, MessageParcel& reply);
    void RemovePermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply);
    void GetPermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply);
    void GetPermissionUsedRecordsAsyncInner(MessageParcel& data, MessageParcel& reply);
    void RegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply);
    void UnRegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply);
    void IsAllowedUsingPermissionInner(MessageParcel& data, MessageParcel& reply);
    bool IsAccessTokenCalling() const;
    bool VerifyPermission(const std::string& permission) const;
    static const int32_t ACCESSTOKEN_UID = 3020;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_STUB_H
