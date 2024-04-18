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

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AtManagerAsyncWorkData"
};
}

int32_t NapiContextCommon::GetJsErrorCode(int32_t errCode)
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
        default:
            jsCode = JS_ERROR_INNER;
            break;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetJsErrorCode nativeCode(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

AtManagerAsyncWorkData::AtManagerAsyncWorkData(napi_env envValue)
{
    env = envValue;
}

AtManagerAsyncWorkData::~AtManagerAsyncWorkData()
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid env");
        return;
    }
    std::unique_ptr<uv_work_t> workPtr = std::make_unique<uv_work_t>();
    std::unique_ptr<AtManagerAsyncWorkDataRel> workDataRel = std::make_unique<AtManagerAsyncWorkDataRel>();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    if ((loop == nullptr) || (workPtr == nullptr) || (workDataRel == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to init execution environment");
        return;
    }
    workDataRel->env = env;
    workDataRel->work = work;
    workDataRel->callbackRef = callbackRef;
    workPtr->data = reinterpret_cast<void *>(workDataRel.get());
    NAPI_CALL_RETURN_VOID(env, uv_queue_work_with_qos(loop, workPtr.get(), [] (uv_work_t *work) {},
        [] (uv_work_t *work, int status) {
            if (work == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "work is nullptr");
                return;
            }
            auto workDataRel = reinterpret_cast<AtManagerAsyncWorkDataRel *>(work->data);
            if (workDataRel == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "workDataRel is nullptr");
                delete work;
                return;
            }
            if (workDataRel->work != nullptr) {
                napi_delete_async_work(workDataRel->env, workDataRel->work);
            }
            if (workDataRel->callbackRef != nullptr) {
                napi_delete_reference(workDataRel->env, workDataRel->callbackRef);
            }
            delete workDataRel;
            delete work;
        }, uv_qos_default));
    workDataRel.release();
    workPtr.release();
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS