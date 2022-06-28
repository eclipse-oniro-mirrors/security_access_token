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
#ifndef  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H_
#define  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H_

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PrivacyAsyncWorkData {
    explicit PrivacyAsyncWorkData(napi_env env);
    virtual ~PrivacyAsyncWorkData();

    napi_env        env = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_deferred   deferred = nullptr;
    napi_ref        callbackRef = nullptr;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_PRIVACY_KITS_NAPI_COMMON_H_ */
