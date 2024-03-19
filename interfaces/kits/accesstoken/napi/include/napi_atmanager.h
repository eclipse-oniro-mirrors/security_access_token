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
#ifndef  INTERFACES_KITS_ACCESSTOKEN_NAPI_INCLUDE_NAPI_ATMANAGER_H
#define  INTERFACES_KITS_ACCESSTOKEN_NAPI_INCLUDE_NAPI_ATMANAGER_H

#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <uv.h>
#include <thread>

#include "ability.h"
#include "ability_context.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "napi_common.h"
#include "napi_error.h"
#include "napi_context_common.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "permission_grant_info.h"
#include "perm_state_change_callback_customize.h"
#include "token_callback_stub.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int AT_PERM_OPERA_FAIL = -1;
const int AT_PERM_OPERA_SUCC = 0;
const int32_t PARAM_DEFAULT_VALUE = -1;

enum PermissionStateChangeType {
    PERMISSION_REVOKED_OPER = 0,
    PERMISSION_GRANTED_OPER = 1,
};

static thread_local napi_ref g_atManagerRef_;
const std::string ATMANAGER_CLASS_NAME = "atManager";
static int32_t curRequestCode_ = 0;
class RegisterPermStateChangeScopePtr : public std::enable_shared_from_this<RegisterPermStateChangeScopePtr>,
    public PermStateChangeCallbackCustomize {
public:
    explicit RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo);
    ~RegisterPermStateChangeScopePtr() override;
    void PermStateChangeCallback(PermStateChangeInfo& result) override;
    void SetEnv(const napi_env& env);
    void SetCallbackRef(const napi_ref& ref);
    void SetValid(bool valid);
    void DeleteNapiRef();
private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    bool valid_ = true;
    std::mutex validMutex_;
};

struct RegisterPermStateChangeWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    PermStateChangeInfo result;
    std::shared_ptr<RegisterPermStateChangeScopePtr> subscriber = nullptr;
};

struct PermStateChangeContext {
    virtual ~PermStateChangeContext();
    napi_env env = nullptr;
    napi_ref callbackRef =  nullptr;
    int32_t errCode = RET_SUCCESS;
    std::string permStateChangeType;
    AccessTokenKit* accessTokenKit = nullptr;
    std::thread::id threadId_;
    std::shared_ptr<RegisterPermStateChangeScopePtr> subscriber = nullptr;
};

typedef PermStateChangeContext RegisterPermStateChangeInfo;

struct UnregisterPermStateChangeInfo : public PermStateChangeContext {
    PermStateChangeScope scopeInfo;
};

struct AtManagerAsyncContext : public AtManagerAsyncWorkData {
    explicit AtManagerAsyncContext(napi_env env) : AtManagerAsyncWorkData(env) {}

    AccessTokenID tokenId = 0;
    std::string permissionName;
    union {
        uint32_t flag = 0;
        uint32_t status;
    };
    int32_t result = AT_PERM_OPERA_FAIL;
    int32_t errorCode = 0;
};

struct PermissionStatusCache {
    int32_t status;
    std::string paramValue;
};

struct PermissionParamCache {
    long long sysCommitIdCache = PARAM_DEFAULT_VALUE;
    int32_t commitIdCache = PARAM_DEFAULT_VALUE;
    int32_t handle = PARAM_DEFAULT_VALUE;
    std::string sysParamCache;
};

struct RequestAsyncContext : public AtManagerAsyncWorkData {
    explicit RequestAsyncContext(napi_env env) : AtManagerAsyncWorkData(env)
    {
        this->env = env;
    }

    AccessTokenID tokenId = 0;
    bool needDynamicRequest = true;
    int32_t result = AT_PERM_OPERA_SUCC;
    std::vector<std::string> permissionList;
    std::vector<int32_t> permissionsState;
    napi_value requestResult = nullptr;
    std::vector<bool> dialogShownResults;
    std::vector<int32_t> permissionQueryResults;
    PermissionGrantInfo info;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<AbilityRuntime::UIExtensionContext> uiExtensionContext;
    bool uiAbilityFlag = false;
};

struct RequestAsyncContextHandle {
    explicit RequestAsyncContextHandle(std::shared_ptr<RequestAsyncContext>& requestAsyncContext)
    {
        asyncContextPtr = requestAsyncContext;
    }

    std::shared_ptr<RequestAsyncContext> asyncContextPtr;
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

struct ResultCallback {
    std::vector<std::string> permissions;
    std::vector<int32_t> grantResults;
    std::vector<bool> dialogShownResults;
    int32_t requestCode;
    std::shared_ptr<RequestAsyncContext> data = nullptr;
};

class AuthorizationResult : public Security::AccessToken::TokenCallbackStub {
public:
    AuthorizationResult(int32_t requestCode, std::shared_ptr<RequestAsyncContext>& data)
        : requestCode_(requestCode), data_(data)
    {}
    virtual ~AuthorizationResult() override = default;

    virtual void GrantResultsCallback(const std::vector<std::string>& permissions,
        const std::vector<int>& grantResults) override;

private:
    int32_t requestCode_ = 0;
    std::shared_ptr<RequestAsyncContext> data_ = nullptr;
};

class NapiAtManager {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static napi_value CreateAtManager(napi_env env, napi_callback_info cbInfo);
    static napi_value VerifyAccessToken(napi_env env, napi_callback_info info);
    static napi_value VerifyAccessTokenSync(napi_env env, napi_callback_info info);
    static napi_value GrantUserGrantedPermission(napi_env env, napi_callback_info info);
    static napi_value RevokeUserGrantedPermission(napi_env env, napi_callback_info info);
    static napi_value CheckAccessToken(napi_env env, napi_callback_info info);
    static napi_value GetPermissionFlags(napi_env env, napi_callback_info info);
    static napi_value GetVersion(napi_env env, napi_callback_info info);
    static napi_value SetPermissionRequestToggleStatus(napi_env env, napi_callback_info info);
    static napi_value GetPermissionRequestToggleStatus(napi_env env, napi_callback_info info);

    static bool ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static bool ParseInputSetToggleStatus(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static bool ParseInputGetToggleStatus(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void VerifyAccessTokenExecute(napi_env env, void *data);
    static void VerifyAccessTokenComplete(napi_env env, napi_status status, void *data);
    static void CheckAccessTokenExecute(napi_env env, void* data);
    static void CheckAccessTokenComplete(napi_env env, napi_status status, void* data);
    static bool ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void GrantUserGrantedPermissionExecute(napi_env env, void *data);
    static void GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void RevokeUserGrantedPermissionExecute(napi_env env, void *data);
    static void RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void GetVersionExecute(napi_env env, void *data);
    static void GetVersionComplete(napi_env env, napi_status status, void *data);
    static void GetPermissionFlagsExecute(napi_env env, void *data);
    static void GetPermissionFlagsComplete(napi_env env, napi_status status, void *data);
    static void SetPermissionRequestToggleStatusExecute(napi_env env, void *data);
    static void SetPermissionRequestToggleStatusComplete(napi_env env, napi_status status, void *data);
    static void GetPermissionRequestToggleStatusExecute(napi_env env, void *data);
    static void GetPermissionRequestToggleStatusComplete(napi_env env, napi_status status, void *data);
    static void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName);
    static void CreateObjects(napi_env env, napi_value exports);
    static bool FillPermStateChangeInfo(const napi_env env, const napi_value* argv, const std::string& type,
        const napi_value thisVar, RegisterPermStateChangeInfo& registerPermStateChangeInfo);
    static bool ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
        RegisterPermStateChangeInfo& registerPermStateChangeInfo);
    static napi_value RegisterPermStateChangeCallback(napi_env env, napi_callback_info cbInfo);
    static bool IsExistRegister(const napi_env env, const RegisterPermStateChangeInfo* registerPermStateChangeInfo);
    static bool ParseInputToUnregister(const napi_env env, napi_callback_info cbInfo,
        UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo);
    static napi_value UnregisterPermStateChangeCallback(napi_env env, napi_callback_info cbInfo);
    static bool FindAndGetSubscriberInVector(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo,
        std::vector<RegisterPermStateChangeInfo*>& batchPermStateChangeRegisters, const napi_env env);
    static void DeleteRegisterFromVector(const PermStateChangeScope& scopeInfo, const napi_env env,
        napi_ref subscriberRef);
    static std::string GetPermParamValue();
    static void UpdatePermissionCache(AtManagerAsyncContext* asyncContext);
    static napi_value RequestPermissionsFromUser(napi_env env, napi_callback_info info);
    static napi_value GetPermissionsStatus(napi_env env, napi_callback_info info);
    static bool ParseRequestPermissionFromUser(
        const napi_env& env, const napi_callback_info& cbInfo, std::shared_ptr<RequestAsyncContext>& asyncContext);
    static bool ParseInputToGetQueryResult(
        const napi_env& env, const napi_callback_info& cbInfo, RequestAsyncContext& asyncContext);
    static void RequestPermissionsFromUserComplete(napi_env env, napi_status status, void* data);
    static void RequestPermissionsFromUserExecute(napi_env env, void* data);
    static void GetPermissionsStatusComplete(napi_env env, napi_status status, void* data);
    static void GetPermissionsStatusExecute(napi_env env, void* data);
    static bool IsDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  INTERFACES_KITS_ACCESSTOKEN_NAPI_INCLUDE_NAPI_ATMANAGER_H */
