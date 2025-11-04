/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_request_global_switch_on_setting.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "ani_common.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string GLOBAL_SWITCH_KEY = "ohos.user.setting.global_switch";
const std::string GLOBAL_SWITCH_RESULT_KEY = "ohos.user.setting.global_switch.result";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
std::shared_ptr<RequestInstanceControl> g_requestInstanceControl = nullptr;
std::mutex g_requestInstanceControlLock;

// error code from dialog
constexpr int32_t REQUEST_ALREADY_EXIST = 1;
constexpr int32_t GLOBAL_TYPE_IS_NOT_SUPPORT = 2;
constexpr int32_t SWITCH_IS_ALREADY_OPEN = 3;
}

static std::shared_ptr<RequestInstanceControl> GetRequestInstanceControl()
{
    std::lock_guard<std::mutex> lock(g_requestInstanceControlLock);
    if (g_requestInstanceControl == nullptr) {
        g_requestInstanceControl = std::make_shared<RequestInstanceControl>();
    }
    return g_requestInstanceControl;
}

RequestGlobalSwitchAsyncContext::RequestGlobalSwitchAsyncContext(ani_vm* vm, ani_env* env)
    : RequestAsyncContextBase(vm, env, REQUEST_GLOBAL_SWITCH_ON_SETTING)
{}

RequestGlobalSwitchAsyncContext::~RequestGlobalSwitchAsyncContext()
{
    Clear();
}

int32_t RequestGlobalSwitchAsyncContext::ConvertErrorCode(int32_t errCode)
{
    int32_t stsCode = STS_OK;
    switch (errCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case REQUEST_ALREADY_EXIST:
            stsCode = STS_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case GLOBAL_TYPE_IS_NOT_SUPPORT:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case SWITCH_IS_ALREADY_OPEN:
            stsCode = STS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN;
            break;
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Dialog error(%{public}d) stsCode(%{public}d).", errCode, stsCode);
    return stsCode;
}


ani_object RequestGlobalSwitchAsyncContext::WrapResult(ani_env* env)
{
    return CreateBooleanObject(env, this->switchStatus);
}

void RequestGlobalSwitchAsyncContext::ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result)
{
    this->result_.errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->switchStatus = result.GetBoolParam(GLOBAL_SWITCH_RESULT_KEY, 0);
}

void RequestGlobalSwitchAsyncContext::StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(this->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "BundleName: %{public}s, permStateAbilityName: %{public}s.",
        this->info.grantBundleName.c_str(), this->info.permStateAbilityName.c_str());
    OHOS::AAFwk::Want want;
    want.SetElementName(this->info.grantBundleName, this->info.globalSwitchAbilityName);
    want.SetParam(GLOBAL_SWITCH_KEY, this->switchType);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    CreateUIExtension(want, asyncContext, GetRequestInstanceControl());
}

bool RequestGlobalSwitchAsyncContext::IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return false;
    }
    auto ptr = std::static_pointer_cast<RequestGlobalSwitchAsyncContext>(other);
    return switchType == ptr->switchType;
}

void RequestGlobalSwitchAsyncContext::CopyResult(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return;
    }
    auto ptr = std::static_pointer_cast<RequestGlobalSwitchAsyncContext>(other);
    this->result_.errorCode = ptr->result_.errorCode;
    this->switchStatus = ptr->switchStatus;
    this->needDynamicRequest_ = false;
}

bool RequestGlobalSwitchAsyncContext::CheckDynamicRequest()
{
    if (!this->needDynamicRequest_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission extension");
        FinishCallback();
        return false;
    }
    return true;
}

bool RequestGlobalSwitchAsyncContext::NoNeedUpdate()
{
    return result_.errorCode != RET_SUCCESS || switchStatus == false;
}

void RequestGlobalSwitchAsyncContext::ProcessFailResult(int32_t code)
{
    if (code == -1) {
        result_.errorCode = code;
    }
}

static bool ParseRequestGlobalSwitch(ani_env* env, ani_object& aniContext, ani_int type,
    ani_object callback, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    asyncContext->switchType = static_cast<SwitchType>(type);

    if (!asyncContext->FillInfoFromContext(aniContext)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef_)) {
        return false;
    }
    return true;
}

void RequestGlobalSwitchExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_int type, ani_object callback)
{
    if (env == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or permissionList or callback is null.");
        return;
    }

    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetVM, error=%{public}u.", status);
        return;
    }
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext =
        std::make_shared<RequestGlobalSwitchAsyncContext>(vm, env);
    if (!ParseRequestGlobalSwitch(env, aniContext, type, callback, asyncContext)) {
        return;
    }

    ani_ref undefRef = nullptr;
    env->GetUndefined(&undefRef);
    ani_object result = reinterpret_cast<ani_object>(undefRef);
    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG, "The context tokenID %{public}d is not same with selfTokenID %{public}d.",
            asyncContext->tokenId, selfTokenID);
        ani_object error =
            BusinessErrorAni::CreateError(env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID,
            "The specified context does not belong to the current application."));
        (void)ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    asyncContext->GetInstanceId();
    GetRequestInstanceControl()->AddCallbackByInstanceId(asyncContext);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog");

    if (asyncContext->result_.errorCode != RET_SUCCESS) {
        asyncContext->FinishCallback();
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS