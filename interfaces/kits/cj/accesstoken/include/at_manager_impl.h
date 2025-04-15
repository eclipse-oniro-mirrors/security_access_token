/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_ACCESS_AT_MANAGER_IMPL_H
#define OHOS_ABILITY_ACCESS_AT_MANAGER_IMPL_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <thread>

#include "accesstoken_kit.h"
#include "cj_common_ffi.h"
#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "permission_grant_info.h"
#include "token_callback_stub.h"
#include "ui_content.h"
#include "ui_extension_context.h"

struct CArrBool {
    void* head;
    int64_t size;
};

struct CPermissionRequestResult {
    CArrString permissions;
    CArrI32 authResults;
    CArrBool dialogShownResults;
};

struct RetDataCPermissionRequestResult {
    int32_t code;
    CPermissionRequestResult data;
};

namespace OHOS {
namespace CJSystemapi {

using namespace OHOS::Security::AccessToken;

const int AT_PERM_OPERA_FAIL = -1;
const int AT_PERM_OPERA_SUCC = 0;
const int32_t PARAM_DEFAULT_VALUE = -1;

struct GrantStatusCache {
    int32_t status;
    std::string paramValue;
};

struct PermissionParamCache {
    long long sysCommitIdCache = PARAM_DEFAULT_VALUE;
    int32_t commitIdCache = PARAM_DEFAULT_VALUE;
    int32_t handle = PARAM_DEFAULT_VALUE;
    std::string sysParamCache;
};

struct CPermStateChangeInfo {
    int32_t permStateChangeType;
    AccessTokenID tokenID;
    char* permissionName;
};

struct RequestAsyncContext {
    AccessTokenID tokenId = 0;
    bool needDynamicRequest = true;
    int32_t result = AT_PERM_OPERA_SUCC;
    std::vector<std::string> permissionList;
    std::vector<int32_t> permissionsState;
    std::vector<bool> dialogShownResults;
    PermissionGrantInfo info;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
    bool uiAbilityFlag = false;
    std::function<void(RetDataCPermissionRequestResult)> callbackRef =  nullptr;
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext);
    ~UIExtensionCallback();
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void ReleaseOrErrorHandle(int32_t code);

private:
    int32_t sessionId_ = 0;
    std::shared_ptr<RequestAsyncContext> reqContext_ = nullptr;
};

class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
public:
    explicit AuthorizationResult(std::shared_ptr<RequestAsyncContext>& data) : data_(data) {}
    ~AuthorizationResult() override = default;
    void GrantResultsCallback(const std::vector<std::string>& permissions,
        const std::vector<int>& grantResults) override;

private:
    std::shared_ptr<RequestAsyncContext> data_ = nullptr;
};

class RegisterPermStateChangeScopePtr : public std::enable_shared_from_this<RegisterPermStateChangeScopePtr>,
    public PermStateChangeCallbackCustomize {
public:
    explicit RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo);
    ~RegisterPermStateChangeScopePtr() override;
    void PermStateChangeCallback(PermStateChangeInfo& result) override;
    void SetCallbackRef(const std::function<void(CPermStateChangeInfo)>& ref);
    void SetValid(bool valid);

private:
    std::function<void(CPermStateChangeInfo)> ref_;
    bool valid_ = true;
    std::mutex validMutex_;
};

struct PermStateChangeContext {
    virtual ~PermStateChangeContext();
    int64_t callbackRef =  0;
    int32_t errCode = 0;
    std::string permStateChangeType;
    AccessTokenKit* accessTokenKit = nullptr;
    std::thread::id threadId;
    std::shared_ptr<RegisterPermStateChangeScopePtr> subscriber = nullptr;
};

typedef PermStateChangeContext RegisterPermStateChangeInfo;

struct UnregisterPermStateChangeInfo : public PermStateChangeContext {
    PermStateChangeScope scopeInfo;
};

class AtManagerImpl {
public:
    static int32_t VerifyAccessTokenSync(unsigned int tokenID, const char* cPermissionName);
    static int32_t GrantUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags);
    static int32_t RevokeUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags);
    static int32_t RegisterPermStateChangeCallback(
        const char* cType,
        CArrUI32 cTokenIDList,
        CArrString cPermissionList,
        int64_t callbackRef);
    static int32_t UnregisterPermStateChangeCallback(
        const char* cType, CArrUI32 cTokenIDList,
        CArrString cPermissionList,
        int64_t callbackRef);
    static void RequestPermissionsFromUser(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
        const std::function<void(RetDataCPermissionRequestResult)>& callbackRef);
private:
    static std::string GetPermParamValue();
    static int32_t FillPermStateChangeInfo(
        const std::string& type,
        CArrUI32 cTokenIDList,
        CArrString cPermissionList,
        int64_t callback,
        RegisterPermStateChangeInfo& registerPermStateChangeInfo);
    static int32_t FillUnregisterPermStateChangeInfo(
        const std::string& type,
        CArrUI32 cTokenIDList,
        CArrString cPermissionList,
        int64_t callback,
        UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo);
    static bool IsExistRegister(const RegisterPermStateChangeInfo* registerPermStateChangeInfo);
    static bool IsDynamicRequest(const std::vector<std::string>& permissions,
        std::vector<int32_t>& permissionsState, std::vector<bool>& dialogShownResults, PermissionGrantInfo& info);
    static bool FindAndGetSubscriberInVector(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo,
        std::vector<RegisterPermStateChangeInfo*>& batchPermStateChangeRegisters);
    static void DeleteRegisterFromVector(const PermStateChangeScope& scopeInfo, int64_t subscriberRef);
    static bool ParseRequestPermissionFromUser(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
        const std::function<void(RetDataCPermissionRequestResult)>& callbackRef,
        const std::shared_ptr<RequestAsyncContext>& asyncContext);
};
}
}

#endif