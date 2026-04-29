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

#ifndef NAPI_CLAW_PERMISSION_H
#define NAPI_CLAW_PERMISSION_H

#include <string>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "claw_permission_info.h"
#include "napi/native_api.h"
#include "napi_context_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ClawPermissionApiType {
    GET_CLI_PERMISSION_DIALOG_INFO,
    GET_SKILL_PERMISSION_DIALOG_INFO,
    GET_CLI_PERMISSIONS,
    GET_SKILL_PERMISSIONS,
    GENERATE_CLI_AUTH_RESULT,
    GENERATE_SKILL_AUTH_RESULT,
};

struct ClawPermissionAsyncContext : public AtManagerAsyncWorkData {
    explicit ClawPermissionAsyncContext(napi_env env) : AtManagerAsyncWorkData(env) {}
    ~ClawPermissionAsyncContext() override = default;

    ClawPermissionApiType apiType = ClawPermissionApiType::GET_CLI_PERMISSION_DIALOG_INFO;
    int32_t errorCode = RET_SUCCESS;
    std::string errorMsg;
    AccessTokenID hostTokenID = 0;
    std::string agentID;
    std::vector<CliInfo> cliInfoList;
    std::vector<SkillInfo> skillInfoList;
    std::vector<CliAuthInfo> cliAuthInfoList;
    std::vector<SkillAuthInfo> skillAuthInfoList;
    PermissionDialogResult dialogResult;
    CliPermissionsResult cliPermissionsResult;
    SkillPermissionsResult skillPermissionsResult;
    ToolAuthResult toolAuthResult;
};

class NapiClawPermission {
public:
    static napi_value GetCliPermissionRequestInfo(napi_env env, napi_callback_info info);
    static napi_value GetSkillPermissionRequestInfo(napi_env env, napi_callback_info info);
    static napi_value GetCliPermissions(napi_env env, napi_callback_info info);
    static napi_value GetSkillPermissions(napi_env env, napi_callback_info info);
    static napi_value GenerateCliAuthResult(napi_env env, napi_callback_info info);
    static napi_value GenerateSkillAuthResult(napi_env env, napi_callback_info info);
    static void Execute(napi_env env, void* data);
    static void Complete(napi_env env, napi_status status, void* data);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // NAPI_CLAW_PERMISSION_H
