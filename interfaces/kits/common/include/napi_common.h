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

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const int ARGS_TWO = 2;
const int ARGS_THREE = 3;
const int ARGS_FIVE = 5;
const int ASYNC_CALL_BACK_VALUES_NUM = 2;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;

bool ParseBool(const napi_env env, const napi_value value);
int32_t ParseInt32(const napi_env env, const napi_value value);
int64_t ParseInt64(const napi_env env, const napi_value value);
uint32_t ParseUint32(const napi_env env, const napi_value value);
std::string ParseString(const napi_env env, const napi_value value);
std::vector<std::string> ParseStringArray(const napi_env env, const napi_value value);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H */

