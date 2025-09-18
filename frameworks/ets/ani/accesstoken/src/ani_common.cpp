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
#include "ani_common.h"
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include <sstream>
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* WRAPPER_CLASS_NAME = "L@ohos/abilityAccessCtrl/AsyncCallbackWrapper;";
constexpr const char* INVOKE_METHOD_NAME = "invoke";
static const int32_t NUM_TWENTY_FOUR = 24;
} // namespace

int32_t GetDifferRequestErrorCode(const ReqPermFromUserErrorCode& errorCode, const AniRequestType& contextType)
{
    return static_cast<int32_t>(errorCode | (contextType << NUM_TWENTY_FOUR));
}

bool ExecuteAsyncCallback(ani_env* env, ani_object callback, ani_object error, ani_object result)
{
    if (env == nullptr || callback == nullptr || error == nullptr || result == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid paramter.");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class clsCall {};

    if ((status = env->FindClass(WRAPPER_CLASS_NAME, &clsCall)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass, error=%{public}u.", status);
        return false;
    }
    ani_method method = {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Class_FindMethod, error=%{public}u.", status);
        return false;
    }

    status = env->Object_CallMethod_Void(static_cast<ani_object>(callback), method, error, result);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_CallMethod_Void, error=%{public}u.", status);
        return false;
    }
    return true;
}

OHOS::Ace::UIContent* GetUIContent(const std::shared_ptr<OHOS::AbilityRuntime::Context> stageContext)
{
    if (stageContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "stageContext is nullptr");
        return nullptr;
    }
    OHOS::Ace::UIContent* uiContent = nullptr;
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(
        stageContext);
    if (abilityContext != nullptr) {
        uiContent = abilityContext->GetUIContent();
    } else {
        auto uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(stageContext);
        if (uiExtensionContext == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to ConvertTo UIExtensionContext.");
            return nullptr;
        }
        uiContent = uiExtensionContext->GetUIContent();
    }
    return uiContent;
}

void CreateUIExtensionMainThread(std::shared_ptr<RequestAsyncContextBase> asyncContext,
    const OHOS::AAFwk::Want& want, const OHOS::Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback> uiExtCallback)
{
    if (asyncContext == nullptr || uiExtCallback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "asyncContext or uiExtCallback is nullptr");
        return;
    }
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        OHOS::Ace::UIContent* uiContent = GetUIContent(asyncContext->stageContext_);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            asyncContext->result_.errorCode = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            return;
        }

        OHOS::Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        LOGI(ATM_DOMAIN, ATM_TAG, "Create end, sessionId: %{public}d, tokenId: %{public}d.",
            sessionId, asyncContext->tokenId);
        if (sessionId <= 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Create component failed, sessionId is invalid");
            asyncContext->result_.errorCode = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
                HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE",
                GetDifferRequestErrorCode(CREATE_MODAL_UI_FAILED, asyncContext->contextType_));
            return;
        }
        uiExtCallback->SetSessionId(sessionId);
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:CreateUIExtensionMainThread");
    } else {
        task();
    }
#else
    task();
#endif
}

void CloseModalUIExtensionMainThread(std::shared_ptr<RequestAsyncContextBase> asyncContext, int32_t sessionId)
{
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "asyncContext is nullptr");
        return;
    }
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->stageContext_);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            asyncContext->result_.errorCode = RET_FAILED;
            return;
        }
        uiContent->CloseModalUIExtension(sessionId);
        LOGI(ATM_DOMAIN, ATM_TAG, "Close end, sessionId: %{public}d", sessionId);
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:CloseModalUIExtensionMainThread");
    } else {
        task();
    }
#else
    task();
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d", asyncContext->instanceId);
}

void CreateUIExtension(
    const OHOS::AAFwk::Want& want,
    std::shared_ptr<RequestAsyncContextBase> asyncContext,
    std::shared_ptr<RequestInstanceControl> controller)
{
    if (asyncContext == nullptr || controller == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "asyncContext or controller is nullptr");
        return;
    }
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    uiExtCallback->SetRequestInstanceControl(controller);
    OHOS::Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](
            int32_t resultCode, const OHOS::AAFwk::Want& result) { uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& receive) { uiExtCallback->OnReceive(receive); },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]] const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); },
    };
    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS