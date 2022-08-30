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
#ifndef  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H
#define  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H

#include <string>
#include <vector>

#include "access_token.h"
#include "active_change_response_info.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_context_common.h"
#include "permission_used_request.h"
#include "permission_used_result.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct RecordManagerAsyncContext : public PrivacyAsyncWorkData {
    explicit RecordManagerAsyncContext(napi_env env) : PrivacyAsyncWorkData(env) {}

    AccessTokenID   tokenId = 0;
    std::string     permissionName;
    int32_t         successCount = 0;
    int32_t         failCount = 0;
    PermissionUsedRequest request;
    PermissionUsedResult result;
    int32_t retCode = -1;
};

typedef PermActiveChangeContext RegisterPermActiveChangeContext;

struct UnregisterPermActiveChangeContext : public PermActiveChangeContext {
    std::vector<std::string> permList;
};

napi_value AddPermissionUsedRecord(napi_env env, napi_callback_info cbinfo);
napi_value StartUsingPermission(napi_env env, napi_callback_info cbinfo);
napi_value StopUsingPermission(napi_env env, napi_callback_info cbinfo);
napi_value GetPermissionUsedRecords(napi_env env, napi_callback_info cbinfo);
napi_value RegisterPermActiveChangeCallback(napi_env env, napi_callback_info cbInfo);
napi_value UnregisterPermActiveChangeCallback(napi_env env, napi_callback_info cbInfo);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_KITS_PERMISSION_USED_MANAGER_NAPI_H */
