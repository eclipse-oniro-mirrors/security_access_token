/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "napi_common.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "perm_state_change_callback_customize.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int AT_PERM_OPERA_FAIL = -1;
const int AT_PERM_OPERA_SUCC = 0;
const int VERIFY_OR_FLAG_INPUT_MAX_VALUES = 2;
const int GRANT_OR_REVOKE_INPUT_MAX_VALUES = 4;

enum PermissionStateChangeType {
    PERMISSION_REVOKED_OPER = 0,
    PERMISSION_GRANTED_OPER = 1,
};

static thread_local napi_ref atManagerRef_;
const std::string ATMANAGER_CLASS_NAME = "atManager";

class RegisterPermStateChangeScopePtr : public PermStateChangeCallbackCustomize {
public:
    explicit RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo);
    ~RegisterPermStateChangeScopePtr();
    void PermStateChangeCallback(PermStateChangeInfo& result) override;
    void SetEnv(const napi_env& env);
    void SetCallbackRef(const napi_ref& ref);
private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct RegisterPermStateChangeWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    PermStateChangeInfo result;
    RegisterPermStateChangeScopePtr* subscriber = nullptr;
};

struct PermStateChangeContext {
    virtual ~PermStateChangeContext();
    napi_env env = nullptr;
    napi_ref callbackRef =  nullptr;
    int32_t errCode = RET_FAILED;
    std::string permStateChangeType;
    AccessTokenKit* accessTokenKit = nullptr;
    std::shared_ptr<RegisterPermStateChangeScopePtr> subscriber = nullptr;
};

typedef PermStateChangeContext RegisterPermStateChangeInfo;

struct UnregisterPermStateChangeInfo : public PermStateChangeContext {
    PermStateChangeScope scopeInfo;
};

struct AtManagerAsyncContext {
    napi_env env = nullptr;
    uint32_t tokenId = 0;
    char     permissionName[ VALUE_BUFFER_SIZE ] = { 0 };
    size_t   pNameLen = 0;
    int      flag = 0;
    int      result = AT_PERM_OPERA_FAIL; // default failed

    napi_deferred   deferred = nullptr; // promise handle
    napi_ref        callbackRef = nullptr; // callback handle
    napi_async_work work = nullptr; // work handle
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
    static napi_value GetPermissionFlags(napi_env env, napi_callback_info info);
    static napi_value GetVersion(napi_env env, napi_callback_info info);

    static void ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void VerifyAccessTokenExecute(napi_env env, void *data);
    static void VerifyAccessTokenComplete(napi_env env, napi_status status, void *data);
    static void ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void GrantUserGrantedPermissionExecute(napi_env env, void *data);
    static void GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void RevokeUserGrantedPermissionExecute(napi_env env, void *data);
    static void RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void GetVersionExecute(napi_env env, void *data);
    static void GetVersionComplete(napi_env env, napi_status status, void *data);
    static void GetPermissionFlagsExecute(napi_env env, void *data);
    static void GetPermissionFlagsComplete(napi_env env, napi_status status, void *data);
    static void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName);
    static bool ParseInputToRegister(const napi_env env, napi_callback_info cbInfo,
        RegisterPermStateChangeInfo& registerPermStateChangeInfo);
    static napi_value RegisterPermStateChangeCallback(napi_env env, napi_callback_info cbinfo);
    static bool IsExistRegister(const RegisterPermStateChangeInfo* registerPermStateChangeInfo);
    static bool ParseInputToUnregister(const napi_env env, napi_callback_info cbInfo,
        UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo);
    static napi_value UnregisterPermStateChangeCallback(napi_env env, napi_callback_info cbinfo);
    static bool FindAndGetSubscriberInMap(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo);
    static void DeleteRegisterInMap(AccessTokenKit* accessTokenKit, const PermStateChangeScope& scopeInfo);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  INTERFACES_KITS_ACCESSTOKEN_NAPI_INCLUDE_NAPI_ATMANAGER_H */
