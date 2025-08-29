/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "request_global_switch_on_setting.h"
#include "ability_access_ctrl_common.h"
#include "ability.h"
#include "access_token.h"
#include "macro.h"
#include "token_setproc.h"
#include "want.h"

using namespace OHOS::FFI;
using OHOS::Security::AccessToken::AccessTokenID;
using OHOS::Security::AccessToken::AccessTokenKit;

namespace OHOS {
namespace CJSystemapi {
namespace {
const std::string GLOBAL_SWITCH_KEY = "ohos.user.setting.global_switch";
const std::string GLOBAL_SWITCH_RESULT_KEY = "ohos.user.setting.global_switch.result";

// error code from dialog of global switch
const int32_t RET_SUCCESS = 0;
const int32_t REQUEST_ALREADY_EXIST = 1;
const int32_t GLOBAL_TYPE_IS_NOT_SUPPORT = 2;
const int32_t SWITCH_IS_ALREADY_OPEN = 3;

std::mutex g_lockFlag;
}

extern "C" {
static int32_t TransferToCJErrorCode(int32_t errCode)
{
    int32_t cjCode = CJ_OK;
    switch (errCode) {
        case RET_SUCCESS:
            cjCode = CJ_OK;
            break;
        case REQUEST_ALREADY_EXIST:
            cjCode = CJ_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case GLOBAL_TYPE_IS_NOT_SUPPORT:
            cjCode = CJ_ERROR_PARAM_INVALID;
            break;
        case SWITCH_IS_ALREADY_OPEN:
            cjCode = CJ_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN;
            break;
        default:
            cjCode = CJ_ERROR_INNER;
            break;
    }
    return cjCode;
}

void SwitchOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    Ace::UIContent* uiContent = nullptr;
    if (this->reqContext_->uiAbilityFlag) {
        uiContent = this->reqContext_->abilityContext->GetUIContent();
    } else {
        uiContent = this->reqContext_->uiExtensionContext->GetUIContent();
    }
    if (uiContent != nullptr) {
        LOGI("Close uiextension component");
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
    if (code == 0) { // the dialog terminate normally
        return;
    }
    LOGE("ReleaseHandler exception: %{public}d", code);
    RetDataBool ret = {.code = code, .data = this->reqContext_->switchStatus};
    this->reqContext_->callbackRef(ret);
}

SwitchOnSettingUICallback::SwitchOnSettingUICallback(const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

SwitchOnSettingUICallback::~SwitchOnSettingUICallback()
{}

void SwitchOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void SwitchOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    LOGI("OnRelease releaseCode is %{public}d", releaseCode);
    ReleaseHandler(releaseCode);
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void SwitchOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->errorCode = result.GetIntParam(RESULT_ERROR_KEY, -1);
    this->reqContext_->switchStatus = result.GetBoolParam(GLOBAL_SWITCH_RESULT_KEY, false);
    LOGI("ResultCode is %{public}d, errorCode=%{public}d, switchStatus=%{public}d",
        resultCode, this->reqContext_->errorCode, this->reqContext_->switchStatus);

    int32_t cjErrorCode = TransferToCJErrorCode(this->reqContext_->errorCode);
    RetDataBool ret = {.code = cjErrorCode, .data = this->reqContext_->switchStatus};
    this->reqContext_->callbackRef(ret);
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void SwitchOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI("OnReceive called!");
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void SwitchOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGE("OnError: code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());
    ReleaseHandler(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void SwitchOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI("Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void SwitchOnSettingUICallback::OnDestroy()
{
    LOGI("UIExtensionAbility destructed.");
}

static Ace::ModalUIExtensionCallbacks BindCallbacks(std::shared_ptr<SwitchOnSettingUICallback> uiExtCallback)
{
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) {
            uiExtCallback->OnReceive(request);
        },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]]const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback] {
            uiExtCallback->OnDestroy();
        },
    };
    return uiExtensionCallbacks;
}

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    if (asyncContext == nullptr) {
        return CJ_ERROR_INNER;
    }
    Ace::UIContent* uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }

    if (uiContent == nullptr) {
        LOGE("Get ui content failed.");
        return CJ_ERROR_PARAM_INVALID;
    }
    auto uiExtCallback = std::make_shared<SwitchOnSettingUICallback>(asyncContext);
    auto uiExtensionCallbacks = BindCallbacks(uiExtCallback);
    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    if (sessionId == 0) {
        LOGE("CreateModalUIExtension failed.");
        return CJ_ERROR_INNER;
    }
    uiExtCallback->SetSessionId(sessionId);
    return CJ_OK;
}

static int32_t StartUIExtension(std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI("bundleName: %{public}s, globalSwitchAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.globalSwitchAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.globalSwitchAbilityName);
    want.SetParam(GLOBAL_SWITCH_KEY, asyncContext->switchType);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

void FfiRequestGlobalSwitchOnSetting::RequestGlobalSwitch(OHOS::AbilityRuntime::Context* context, int32_t switchType,
    const std::function<void(RetDataBool)>& callbackRef)
{
    RetDataBool ret = {.code = CJ_ERROR_INNER, .data = false};
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext = std::make_shared<RequestGlobalSwitchAsyncContext>();
    if (!ParseRequestGlobalSwitch(context, asyncContext)) {
        LOGE("RequestGlobalSwitch param invalid.");
        ret.code = CJ_ERROR_PARAM_INVALID;
        callbackRef(ret);
        return;
    }
    asyncContext->switchType = switchType;
    asyncContext->callbackRef = callbackRef;

    int32_t result = StartUIExtension(asyncContext);
    ret.code = result;
    if (result != CJ_OK) {
        callbackRef(ret);
    }
    return;
}

bool FfiRequestGlobalSwitchOnSetting::ParseRequestGlobalSwitch(OHOS::AbilityRuntime::Context* context,
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    AccessTokenID tokenID = 0;
    auto contextSharedPtr = context->shared_from_this();
    asyncContext->abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(contextSharedPtr);
    if (asyncContext->abilityContext != nullptr) {
        asyncContext->uiAbilityFlag = true;
        tokenID = asyncContext->abilityContext->GetApplicationInfo()->accessTokenId;
    } else {
        asyncContext->uiExtensionContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(contextSharedPtr);
        if (asyncContext->uiExtensionContext == nullptr) {
            LOGE("Convert to ui extension context failed");
            return false;
        }
        tokenID = asyncContext->uiExtensionContext->GetApplicationInfo()->accessTokenId;
    }
    if (tokenID != static_cast<AccessTokenID>(GetSelfTokenID())) {
        LOGE("tokenID error");
        return false;
    }
    return true;
}
}
} // namespace CJSystemapi
} // namespace OHOS
