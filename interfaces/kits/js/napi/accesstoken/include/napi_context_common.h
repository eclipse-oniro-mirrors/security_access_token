/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifndef INTERFACES_ACCESSTOKEN_KITS_NAPI_CONTEXT_COMMON_H
#define INTERFACES_ACCESSTOKEN_KITS_NAPI_CONTEXT_COMMON_H

#include <uv.h>
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "napi_error.h"
#include "napi_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class NapiContextCommon {
public:
    static constexpr int32_t MAX_PARAMS_ONE = 1;
    static constexpr int32_t MAX_PARAMS_TWO = 2;
    static constexpr int32_t MAX_PARAMS_THREE = 3;
    static constexpr int32_t MAX_PARAMS_FOUR = 4;
    static constexpr int32_t MAX_LENGTH = 256;
    static constexpr int32_t MAX_WAIT_TIME = 1000;
    static constexpr int32_t VALUE_MAX_LEN = 32;

    static int32_t GetJsErrorCode(int32_t errCode);
};
struct AtManagerAsyncWorkData {
    explicit AtManagerAsyncWorkData(napi_env envValue);
    virtual ~AtManagerAsyncWorkData();

    napi_env        env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred   deferred = nullptr;
    napi_ref        callbackRef = nullptr;
};

struct AtManagerAsyncWorkDataRel {
    napi_env        env = nullptr;
    napi_async_work work = nullptr;
    napi_ref        callbackRef = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ACCESSTOKEN_KITS_NAPI_CONTEXT_COMMON_H */
