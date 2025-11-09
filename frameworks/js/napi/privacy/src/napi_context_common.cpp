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
#include "napi_context_common.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
PrivacyAsyncWorkData::PrivacyAsyncWorkData(napi_env envValue)
{
    env = envValue;
}

PrivacyAsyncWorkData::~PrivacyAsyncWorkData()
{
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }

    if (asyncWork != nullptr) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

PermActiveChangeContext::~PermActiveChangeContext()
{}

PermActiveStatusPtr::PermActiveStatusPtr(const std::vector<std::string>& permList)
    : PermActiveStatusCustomizedCbk(permList)
{}

PermActiveStatusPtr::~PermActiveStatusPtr()
{
    if (ref_ == nullptr) {
        return;
    }
    DeleteNapiRef();
}

void PermActiveStatusPtr::DeleteNapiRef()
{
    PermActiveStatusWorker* permActiveStatusWorker = new (std::nothrow) PermActiveStatusWorker();
    if (permActiveStatusWorker == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Insufficient memory for RegisterPermStateChangeWorker!");
        return;
    }
    std::unique_ptr<PermActiveStatusWorker> workPtr {permActiveStatusWorker};
    permActiveStatusWorker->env = env_;
    permActiveStatusWorker->ref = ref_;
    auto task = [permActiveStatusWorker]() {
        napi_delete_reference(permActiveStatusWorker->env, permActiveStatusWorker->ref);
        delete permActiveStatusWorker;
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high, "DeleteNapiRefForPermActiveStatus")) {
        LOGE(PRI_DOMAIN, PRI_TAG, "DeleteNapiRef: Failed to SendEvent");
    } else {
        workPtr.release();
    }
}

void PermActiveStatusPtr::SetEnv(const napi_env& env)
{
    env_ = env;
}

void PermActiveStatusPtr::SetCallbackRef(const napi_ref& ref)
{
    ref_ = ref;
}

void PermActiveStatusPtr::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
    PermActiveStatusWorker* permActiveStatusWorker = new (std::nothrow) PermActiveStatusWorker();
    if (permActiveStatusWorker == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Insufficient memory for RegisterPermStateChangeWorker!");
        return;
    }
    std::unique_ptr<PermActiveStatusWorker> workPtr {permActiveStatusWorker};
    permActiveStatusWorker->env = env_;
    permActiveStatusWorker->ref = ref_;
    permActiveStatusWorker->result = result;
    LOGD(PRI_DOMAIN, PRI_TAG,
        "result: tokenID = %{public}d, permissionName = %{public}s, type = %{public}d",
        result.tokenID, result.permissionName.c_str(), result.type);
    permActiveStatusWorker->subscriber = shared_from_this();
    auto task = [permActiveStatusWorker]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(permActiveStatusWorker->env, &scope);
        if (scope == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Scope is null");
            delete permActiveStatusWorker;
            return;
        }
        NotifyChangeResponse(permActiveStatusWorker);
        napi_close_handle_scope(permActiveStatusWorker->env, scope);
        delete permActiveStatusWorker;
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high, "ActiveStatusChangeCallback")) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ActiveStatusChangeCallback: Failed to SendEvent");
    } else {
        workPtr.release();
    }
}

void NotifyChangeResponse(const PermActiveStatusWorker* permActiveStatusData)
{
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(permActiveStatusData->env,
        napi_create_object(permActiveStatusData->env, &result));
    if (!ConvertActiveChangeResponse(permActiveStatusData->env, result, permActiveStatusData->result)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ConvertActiveChangeResponse failed");
        return;
    }
    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    NAPI_CALL_RETURN_VOID(permActiveStatusData->env,
        napi_get_undefined(permActiveStatusData->env, &undefined));
    NAPI_CALL_RETURN_VOID(permActiveStatusData->env,
        napi_get_reference_value(permActiveStatusData->env, permActiveStatusData->ref, &callback));
    NAPI_CALL_RETURN_VOID(permActiveStatusData->env,
        napi_call_function(permActiveStatusData->env, undefined, callback, 1, &result, &resultOut));
    return;
}

bool ConvertActiveChangeResponse(napi_env env, napi_value value, const ActiveChangeResponse& result)
{
    napi_value element;
    NAPI_CALL_BASE(env, napi_create_uint32(env, result.callingTokenID, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "callingTokenId", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_uint32(env, result.tokenID, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "tokenId", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, result.permissionName.c_str(),
        NAPI_AUTO_LENGTH, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "permissionName", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, result.deviceId.c_str(),
        NAPI_AUTO_LENGTH, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "deviceId", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.type, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "activeStatus", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.usedType, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "usedType", element), false);
    return true;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS