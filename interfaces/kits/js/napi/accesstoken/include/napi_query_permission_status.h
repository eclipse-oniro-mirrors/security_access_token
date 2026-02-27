/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NAPI_QUERY_PERMISSION_STATUS_H
#define NAPI_QUERY_PERMISSION_STATUS_H

#include <napi/native_api.h>
#include <vector>
#include <string>

#include "access_token.h"
#include "napi_common.h"
#include "napi_context_common.h"
#include "permission_status.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct QueryPermissionStatusAsyncContext : public AtManagerAsyncWorkData {
    struct {
        int32_t errorCode = RET_SUCCESS;
        std::string errorMsg;
    } result;

    std::vector<std::string> permissionList;
    std::vector<AccessTokenID> tokenIDList;
    std::vector<PermissionStatus> permissionInfoList;
    bool isQueryByPermission = false;

    explicit QueryPermissionStatusAsyncContext(napi_env env) : AtManagerAsyncWorkData(env) {}
    ~QueryPermissionStatusAsyncContext() override = default;

    void SetErrorCode(int32_t code)
    {
        result.errorCode = code;
    }
};

class NapiQueryPermissionStatus {
public:
    static napi_value QueryStatusByPermission(napi_env env, napi_callback_info info);
    static napi_value QueryStatusByTokenID(napi_env env, napi_callback_info info);

private:
    static void QueryPermissionStatusExecute(napi_env env, void* data);
    static void QueryPermissionStatusComplete(napi_env env, napi_status status, void* data);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // NAPI_QUERY_PERMISSION_STATUS_H
