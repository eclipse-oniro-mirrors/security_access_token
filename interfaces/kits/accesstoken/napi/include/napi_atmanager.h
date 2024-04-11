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
#ifndef INTERFACES_ACCESSTOKEN_KITS_NAPI_ATMANAGER_H
#define INTERFACES_ACCESSTOKEN_KITS_NAPI_ATMANAGER_H

#include "accesstoken_kit.h"
#include "napi_error.h"
#include "napi_context_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int32_t PARAM_DEFAULT_VALUE = -1;

enum PermissionStateChangeType {
    PERMISSION_REVOKED_OPER = 0,
    PERMISSION_GRANTED_OPER = 1,
};

static thread_local napi_ref g_atManagerRef_;
const std::string ATMANAGER_CLASS_NAME = "atManager";
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
    int32_t result = RET_FAILED;
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
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /* INTERFACES_ACCESSTOKEN_KITS_NAPI_ATMANAGER_H */
