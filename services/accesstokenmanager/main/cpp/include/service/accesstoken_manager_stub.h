/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_MANAGER_STUB_H
#define ACCESSTOKEN_MANAGER_STUB_H

#include <map>

#include "i_accesstoken_manager.h"

#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerStub : public IRemoteStub<IAccessTokenManager> {
public:
    AccessTokenManagerStub();
    virtual ~AccessTokenManagerStub();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& options) override;

private:
    void GetUserGrantedPermissionUsedTypeInner(MessageParcel& data, MessageParcel& reply);
    void VerifyAccessTokenInner(MessageParcel& data, MessageParcel& reply);
    void GetDefPermissionInner(MessageParcel& data, MessageParcel& reply);
    void GetDefPermissionsInner(MessageParcel& data, MessageParcel& reply);
    void GetReqPermissionsInner(MessageParcel& data, MessageParcel& reply);
    void GetSelfPermissionsStateInner(MessageParcel& data, MessageParcel& reply);
    void GetPermissionsStatusInner(MessageParcel& data, MessageParcel& reply);
    void GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply);
    void SetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply);
    void GetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply);
    void GrantPermissionInner(MessageParcel& data, MessageParcel& reply);
    void RevokePermissionInner(MessageParcel& data, MessageParcel& reply);
    void ClearUserGrantedPermissionStateInner(MessageParcel& data, MessageParcel& reply);
    void AllocHapTokenInner(MessageParcel& data, MessageParcel& reply);
    void InitHapTokenInner(MessageParcel& data, MessageParcel& reply);
    void DeleteTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void UpdateHapTokenInner(MessageParcel& data, MessageParcel& reply);
    void GetHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void GetNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void AllocLocalTokenIDInner(MessageParcel& data, MessageParcel& reply);
    void GetHapTokenIDInner(MessageParcel& data, MessageParcel& reply);
    void CheckNativeDCapInner(MessageParcel& data, MessageParcel& reply);
    void GetTokenTypeInner(MessageParcel& data, MessageParcel& reply);
    void RegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply);
    void UnRegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply);
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    void ReloadNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply);
#endif
    void GetNativeTokenIdInner(MessageParcel& data, MessageParcel& reply);

#ifdef TOKEN_SYNC_ENABLE
    void GetHapTokenInfoFromRemoteInner(MessageParcel& data, MessageParcel& reply);
    void GetAllNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void SetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void SetRemoteNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void DeleteRemoteTokenInner(MessageParcel& data, MessageParcel& reply);
    void DeleteRemoteDeviceTokensInner(MessageParcel& data, MessageParcel& reply);
    void GetRemoteNativeTokenIDInner(MessageParcel& data, MessageParcel& reply);
    void RegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply);
    void UnRegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply);
    void SetTokenSyncFuncInMap();
#endif
    void SetPermissionOpFuncInMap();
    void SetLocalTokenOpFuncInMap();
    void DumpTokenInfoInner(MessageParcel& data, MessageParcel& reply);
    void DumpPermDefInfoInner(MessageParcel& data, MessageParcel& reply);
    void GetVersionInner(MessageParcel& data, MessageParcel& reply);
    void SetPermDialogCapInner(MessageParcel& data, MessageParcel& reply);

    bool IsPrivilegedCalling() const;
    bool IsAccessTokenCalling();
    bool IsNativeProcessCalling();
    bool IsSystemAppCalling() const;
    bool IsShellProcessCalling();
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    static const int32_t ROOT_UID = 0;
#endif
    static const int32_t ACCESSTOKEN_UID = 3020;

    AccessTokenID tokenSyncId_ = 0;

    using RequestFuncType = void (AccessTokenManagerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, RequestFuncType> requestFuncMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_STUB_H
