/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef NAPI_ATMANAGER_H_
#define NAPI_ATMANAGER_H_

#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#define ASYN_THREAD_EXEC_SUCC 0
#define ASYN_THREAD_EXEC_FAIL -1
#define ACCESSTOKEN_PERMISSION_GRANT_FAIL -1
#define ACCESSTOKEN_PERMISSION_GRANT_SUCC 0
#define ACCESSTOKEN_PERMISSION_REVOKE_FAIL -1
#define ACCESSTOKEN_PERMISSION_REVOKE_SUCC 0
#define VALUE_BUFFER_SIZE 128

static thread_local napi_ref atManagerRef_;
const std::string ATMANAGER_CLASS_NAME = "atManager";

struct AtManagerAsyncContext {
    napi_env env = nullptr;
    uint32_t tokenId = 0;
    char     permissionName[ VALUE_BUFFER_SIZE ] = { 0 };
    size_t   pNameLen = 0;
    int      flag = 0;
    PermissionState grantState = PERMISSION_DENIED;
    int      result = 0; // callback or promise return result
    int      status = ASYN_THREAD_EXEC_FAIL; // napi_create_async_work-execute function exec result, default failure

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
    static napi_value GrantUserGrantedPermission(napi_env env, napi_callback_info info);
    static napi_value RevokeUserGrantedPermission(napi_env env, napi_callback_info info);
    static napi_value GetPermissionFlags(napi_env env, napi_callback_info info);

    static void ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void VerifyAccessTokenExecute(napi_env env, void *data);
    static void VerifyAccessTokenComplete(napi_env env, napi_status status, void *data);
    static void ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
        AtManagerAsyncContext& asyncContext);
    static void GrantUserGrantedPermissionExcute(napi_env env, void *data);
    static void GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void RevokeUserGrantedPermissionExcute(napi_env env, void *data);
    static void RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void *data);
    static void GetPermissionFlagsExcute(napi_env env, void *data);
    static void GetPermissionFlagsComplete(napi_env env, napi_status status, void *data);
    static void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /* NAPI_ATMANAGER_H_ */
