/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <map>

#include "i_privacy_manager.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyManagerStub : public IRemoteStub<IPrivacyManager> {
public:
    PrivacyManagerStub();
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
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    bool HandleSecCompReq(uint32_t code, MessageParcel& data, MessageParcel& reply);
    void RegisterSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply);
    void UpdateSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply);
    void GetSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply);
    void GetSpecialSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply);
    bool IsSecCompServiceCalling();
#endif
    void GetPermissionUsedTypeInfosInner(MessageParcel& data, MessageParcel& reply);
    void SetMutePolicyInner(MessageParcel& data, MessageParcel& reply);
    bool IsAccessTokenCalling() const;
    bool IsSystemAppCalling() const;
    bool VerifyPermission(const std::string& permission) const;
    static const int32_t ACCESSTOKEN_UID = 3020;
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    AccessTokenID secCompTokenId_ = 0;
#endif
    void SetPrivacyFuncInMap();

    using RequestType = void (PrivacyManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestType> requestMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_MANAGER_STUB_H
