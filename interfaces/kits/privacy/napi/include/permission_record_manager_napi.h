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
#ifndef  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H_
#define  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H_

#include <string>

#include "access_token.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "permission_used_request.h"
#include "permission_used_result.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct RecordManagerAsyncContext {
    napi_env        env = nullptr;
    napi_async_work asyncWork = nullptr; 
    napi_deferred   deferred = nullptr;
    napi_ref        callbackRef = nullptr;

    AccessTokenID   tokenId = 0;
    std::string     permissionName;
    int32_t         successCount;
    int32_t         failCount;
    PermissionUsedRequest request;
    PermissionUsedResult result;

    int32_t retCode;
};

napi_value AddPermissionUsedRecord(napi_env env, napi_callback_info cbinfo);
napi_value StartUsingPermission(napi_env env, napi_callback_info cbinfo);
napi_value StopUsingPermission(napi_env env, napi_callback_info cbinfo);
napi_value GetPermissionUsedRecords(napi_env env, napi_callback_info cbinfo);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H_ */
