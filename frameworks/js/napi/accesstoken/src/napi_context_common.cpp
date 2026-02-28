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
#include "napi_context_common.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

int32_t GetJsErrorCode(int32_t errCode)
{
    int32_t jsCode;
    switch (errCode) {
        case RET_SUCCESS:
            jsCode = JS_OK;
            break;
        case ERR_PERMISSION_DENIED:
            jsCode = JS_ERROR_PERMISSION_DENIED;
            break;
        case ERR_NOT_SYSTEM_APP:
            jsCode = JS_ERROR_NOT_SYSTEM_APP;
            break;
        case ERR_PARAM_INVALID:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case ERR_TOKENID_NOT_EXIST:
            jsCode = JS_ERROR_TOKENID_NOT_EXIST;
            break;
        case ERR_PERMISSION_NOT_EXIST:
            jsCode = JS_ERROR_PERMISSION_NOT_EXIST;
            break;
        case ERR_INTERFACE_NOT_USED_TOGETHER:
        case ERR_CALLBACK_ALREADY_EXIST:
            jsCode = JS_ERROR_NOT_USE_TOGETHER;
            break;
        case ERR_CALLBACKS_EXCEED_LIMITATION:
            jsCode = JS_ERROR_REGISTERS_EXCEED_LIMITATION;
            break;
        case ERR_IDENTITY_CHECK_FAILED:
            jsCode = JS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERROR_IPC_REQUEST_FAIL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
            jsCode = JS_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_MALLOC_FAILED:
            jsCode = JS_ERROR_OUT_OF_MEMORY;
            break;
        case ERR_EXPECTED_PERMISSION_TYPE:
            jsCode = JS_ERROR_EXPECTED_PERMISSION_TYPE;
            break;
        case ERR_OVERSIZE:
            jsCode = JS_ERROR_OVERSIZE;
            break;
        default:
            jsCode = JS_ERROR_INNER;
            break;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "GetJsErrorCode nativeCode(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

AtManagerAsyncWorkData::AtManagerAsyncWorkData(napi_env envValue)
{
    env = envValue;
}

AtManagerAsyncWorkData::~AtManagerAsyncWorkData()
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid env");
        return;
    }
    AtManagerAsyncWorkDataRel* workDataRel = new (std::nothrow) AtManagerAsyncWorkDataRel();
    if (workDataRel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "workDataRel is nullptr");
        return;
    }
    std::unique_ptr<AtManagerAsyncWorkDataRel> workDataRelPtr {workDataRel};
    workDataRel->env = env;
    workDataRel->work = work;
    workDataRel->callbackRef = callbackRef;
    auto task = [workDataRel]() {
        if (workDataRel->work != nullptr) {
            napi_delete_async_work(workDataRel->env, workDataRel->work);
        }
        if (workDataRel->callbackRef != nullptr) {
            napi_delete_reference(workDataRel->env, workDataRel->callbackRef);
        }
        delete workDataRel;
    };
    if (napi_status::napi_ok != napi_send_event(env, task, napi_eprio_high, "AtManagerAsyncWorkDataDestructor")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AtManagerAsyncWorkData: Failed to SendEvent");
    } else {
        workDataRelPtr.release();
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS