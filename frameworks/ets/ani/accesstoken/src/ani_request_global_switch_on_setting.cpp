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
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<RequestGlobalSwitchAsyncContext>>>
    RequestGlobalSwitchAsyncInstanceControl::instanceIdMap_;
std::mutex RequestGlobalSwitchAsyncInstanceControl::instanceIdMutex_;
namespace {
const std::string GLOBAL_SWITCH_KEY = "ohos.user.setting.global_switch";
const std::string GLOBAL_SWITCH_RESULT_KEY = "ohos.user.setting.global_switch.result";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

// error code from dialog
constexpr int32_t REQUEST_ALREADY_EXIST = 1;
constexpr int32_t GLOBAL_TYPE_IS_NOT_SUPPORT = 2;
constexpr int32_t SWITCH_IS_ALREADY_OPEN = 3;
}
RequestGlobalSwitchAsyncContext::~RequestGlobalSwitchAsyncContext()
{
    if (vm == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Vm is null.");
        return;
    }
    bool isSameThread = IsCurrentThread(threadId);
    ani_env* curEnv = isSameThread ? env : GetCurrentEnv(vm);
    if (curEnv == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetCurrentEnv.");
        return;
    }

    if (callbackRef != nullptr) {
        curEnv->GlobalReference_Delete(callbackRef);
        callbackRef = nullptr;
    }
}

static ani_status GetContext(
    ani_env* env, const ani_object& aniContext, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetStageModeContext.");
        return ANI_ERROR;
    }
    asyncContext->abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (asyncContext->abilityContext != nullptr) {
        auto abilityInfo = asyncContext->abilityContext->GetApplicationInfo();
        if (abilityInfo == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetApplicationInfo.");
            return ANI_ERROR;
        }
        asyncContext->uiAbilityFlag = true;
        asyncContext->tokenId = abilityInfo->accessTokenId;
    } else {
        asyncContext->uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context);
        if (asyncContext->uiExtensionContext == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to ConvertTo UIExtensionContext.");
            return ANI_ERROR;
        }
        auto uiExtensionInfo = asyncContext->uiExtensionContext->GetApplicationInfo();
        if (uiExtensionInfo == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetApplicationInfo.");
            return ANI_ERROR;
        }
        asyncContext->tokenId = uiExtensionInfo->accessTokenId;
    }
    return ANI_OK;
}

static bool ParseRequestGlobalSwitch(ani_env* env, ani_object& aniContext, ani_int type,
    ani_object callback, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetVM, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }
    asyncContext->vm = vm;
    asyncContext->env = env;
    asyncContext->callback = callback;
    asyncContext->threadId = std::this_thread::get_id();
    asyncContext->switchType = static_cast<SwitchType>(type);

    if (GetContext(env, aniContext, asyncContext) != ANI_OK) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef)) {
        return false;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

static int32_t TransferToStsErrorCode(int32_t errCode)
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

SwitchOnSettingUICallback::SwitchOnSettingUICallback(
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

SwitchOnSettingUICallback::~SwitchOnSettingUICallback()
{}

void SwitchOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

static void GlobalSwitchResultsCallbackUI(bool switchStatus, std::shared_ptr<RequestGlobalSwitchAsyncContext>& data)
{
    bool isSameThread = IsCurrentThread(data->threadId);
    ani_env* env = isSameThread ? data->env : GetCurrentEnv(data->vm);
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetCurrentEnv.");
        return;
    }

    int32_t stsCode = TransferToStsErrorCode(data->result.errorCode);
    ani_object error = BusinessErrorAni::CreateError(env, stsCode, GetErrorMessage(stsCode, data->result.errorMsg));
    ExecuteAsyncCallback(
        env, reinterpret_cast<ani_object>(data->callbackRef), error, CreateBooleanObject(env, data->switchStatus));

    if (!isSameThread && data->vm->DetachCurrentThread() != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to DetachCurrentThread!");
    }
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext,
    int32_t sessionId)
{
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ui content!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }
        uiContent->CloseModalUIExtension(sessionId);
        LOGI(ATM_DOMAIN, ATM_TAG, "Close end, sessionId: %{public}d.", sessionId);
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
}

void SwitchOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(this->reqContext_->lockReleaseFlag);
        if (this->reqContext_->releaseFlag) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    if (code == -1) {
        this->reqContext_->result.errorCode = code;
    }
    RequestGlobalSwitchAsyncInstanceControl::UpdateQueueData(this->reqContext_);
    RequestGlobalSwitchAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    GlobalSwitchResultsCallbackUI(this->reqContext_->switchStatus, this->reqContext_);
}

/*
    * when UIExtensionAbility use terminateSelfWithResult
    */
void SwitchOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->result.errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->switchStatus = result.GetBoolParam(GLOBAL_SWITCH_RESULT_KEY, 0);
    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode is %{public}d,  errorCodeis %{public}d, switchStatus=%{public}d.",
        resultCode, this->reqContext_->result.errorCode, this->reqContext_->switchStatus);
    ReleaseHandler(0);
}

/*
    * when UIExtensionAbility send message to UIExtensionComponent
    */
void SwitchOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
    * when UIExtensionAbility disconnect or use terminate or process die
    * releaseCode is 0 when process normal exit
    */
void SwitchOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ReleaseCode is %{public}d.", releaseCode);

    ReleaseHandler(-1);
}

/*
    * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
    */
void SwitchOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Code is %{public}d, name is %{public}s, message is %{public}s.",
        code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

/*
    * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
    * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
    */
void SwitchOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
    * when UIExtensionComponent destructed
    */
void SwitchOnSettingUICallback::OnDestroy()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<SwitchOnSettingUICallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ui content!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }

        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        LOGI(ATM_DOMAIN, ATM_TAG, "Create end, sessionId: %{public}d, tokenId: %{public}d.",
            sessionId, asyncContext->tokenId);
        if (sessionId == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create component, sessionId is 0.");
            asyncContext->result.errorCode = RET_FAILED;
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

static void CreateUIExtension(
    const OHOS::AAFwk::Want &want, std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    auto uiExtCallback = std::make_shared<SwitchOnSettingUICallback>(asyncContext);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const AAFwk::WantParams& receive) {
            uiExtCallback->OnReceive(receive);
        },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]] const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() {
            uiExtCallback->OnDestroy();
        },
    };

    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
}

static void StartUIExtension(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "BundleName: %{public}s, permStateAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.permStateAbilityName.c_str());
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.globalSwitchAbilityName);
    want.SetParam(GLOBAL_SWITCH_KEY, asyncContext->switchType);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    CreateUIExtension(want, asyncContext);
}

static void GetInstanceId(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ui content!");
            return;
        }
        asyncContext->instanceId = uiContent->GetInstanceId();
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:GetInstanceId");
    } else {
        task();
    }
#else
    task();
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d.", asyncContext->instanceId);
}

void RequestGlobalSwitchAsyncInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InstanceId: %{public}d.", asyncContext->instanceId);
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(asyncContext->instanceId);
        // id is existed mean a pop window is showing, add context to waiting queue
        if (iter != instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "InstanceId: %{public}d has existed.", asyncContext->instanceId);
            instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
            return;
        }
        // make sure id is in map to indicate a pop-up window is showing
        instanceIdMap_[asyncContext->instanceId] = {};
    }
    StartUIExtension(asyncContext);
}

void RequestGlobalSwitchAsyncInstanceControl::UpdateQueueData(
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    if ((reqContext->result.errorCode != RET_SUCCESS) || !(reqContext->switchStatus)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "The queue data does not need to be updated.");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = reqContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        int32_t targetSwitchType = reqContext->switchType;
        LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
        for (auto& asyncContext : iter->second) {
            if (targetSwitchType == asyncContext->switchType) {
                asyncContext->result.errorCode = reqContext->result.errorCode;
                asyncContext->switchStatus = reqContext->switchStatus;
                asyncContext->isDynamic = false;
            }
        }
    }
}

void RequestGlobalSwitchAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext = nullptr;
    bool isDynamic = false;
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        while (!iter->second.empty()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
            asyncContext = iter->second[0];
            iter->second.erase(iter->second.begin());
            CheckDynamicRequest(asyncContext, isDynamic);
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map is empty.", id);
            instanceIdMap_.erase(id);
        }
    }
    if (isDynamic) {
        StartUIExtension(asyncContext);
    }
}

void RequestGlobalSwitchAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext, bool& isDynamic)
{
    isDynamic = asyncContext->isDynamic;
    if (!isDynamic) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission exsion.");
        GlobalSwitchResultsCallbackUI(asyncContext->switchStatus, asyncContext);
        return;
    }
}

void RequestGlobalSwitchExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_int type, ani_object callback)
{
    if (env == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or permissionList or callback is null.");
        return;
    }

    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext =
        std::make_shared<RequestGlobalSwitchAsyncContext>();
    if (!ParseRequestGlobalSwitch(env, aniContext, type, callback, asyncContext)) {
        return;
    }

    ani_object result = CreateBooleanObject(env, false);
    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG, "The context tokenID %{public}d is not same with selfTokenID %{public}d.",
            asyncContext->tokenId, selfTokenID);
        ani_object error =
            BusinessErrorAni::CreateError(env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID,
            "The specified context does not belong to the current application."));
        ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    GetInstanceId(asyncContext);
    RequestGlobalSwitchAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog.");

    if (asyncContext->result.errorCode != RET_SUCCESS) {
        int32_t stsCode = TransferToStsErrorCode(asyncContext->result.errorCode);
        ani_object error = BusinessErrorAni::CreateError(
            env, stsCode, GetErrorMessage(stsCode, asyncContext->result.errorMsg));
        ExecuteAsyncCallback(env, callback, error, result);
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
