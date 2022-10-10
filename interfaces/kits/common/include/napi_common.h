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

#ifndef  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H
#define  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H

#include "access_token.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr int32_t ASYNC_CALL_BACK_VALUES_NUM = 2;
constexpr int32_t ASYNC_CALL_BACK_PARAM_ERROR = 0;
constexpr int32_t ASYNC_CALL_BACK_PARAM_DATA = 1;

bool ParseBool(const napi_env& env, const napi_value& value, bool& result);
bool ParseInt32(const napi_env& env, const napi_value& value, int32_t& result);
bool ParseInt64(const napi_env& env, const napi_value& value, int64_t& result);
bool ParseUint32(const napi_env& env, const napi_value& value, uint32_t& result);
bool ParseString(const napi_env& env, const napi_value& value, std::string& result);
bool ParseStringArray(const napi_env& env, const napi_value& value, std::vector<std::string>& result);
bool ParseAccessTokenIDArray(const napi_env& env, const napi_value& value, std::vector<AccessTokenID>& result);
bool ParseCallback(const napi_env& env, const napi_value& value, napi_ref& result);
bool IsArray(const napi_env& env, const napi_value& value);
bool CheckType(const napi_env& env, const napi_value& value, const napi_valuetype& type);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /* INTERFACES_PRIVACY_KITS_NAPI_COMMON_H */

