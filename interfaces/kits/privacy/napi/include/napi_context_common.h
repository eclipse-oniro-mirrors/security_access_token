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
#ifndef  INTERFACES_PRIVACY_KITS_NAPI_CONTEXT_COMMON_H
#define  INTERFACES_PRIVACY_KITS_NAPI_CONTEXT_COMMON_H

#include <uv.h>
#include "accesstoken_log.h"
#include "active_change_response_info.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common.h"
#include "perm_active_status_customized_cbk.h"
#include "privacy_kit.h"

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

class PermActiveStatusPtr : public PermActiveStatusCustomizedCbk {
public:
    explicit PermActiveStatusPtr(const std::vector<std::string>& permList);
    ~PermActiveStatusPtr();
    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
    void SetEnv(const napi_env& env);
    void SetCallbackRef(const napi_ref& ref);
private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct PermActiveStatusWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    ActiveChangeResponse result;
    PermActiveStatusPtr* subscriber = nullptr; // this
};

struct PermActiveChangeContext {
    virtual ~PermActiveChangeContext();

    napi_env env = nullptr;
    napi_ref callbackRef = nullptr;
    std::string type;
    std::shared_ptr<PermActiveStatusPtr> subscriber = nullptr;
};

void UvQueueWorkActiveStatusChange(uv_work_t* work, int status);
bool ConvertActiveChangeResponse(napi_env env, napi_value value, const ActiveChangeResponse& result);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_PRIVACY_KITS_NAPI_CONTEXT_COMMON_H */
