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
#include "ani_request_base.h"

#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "ani_common.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

RequestAsyncContextBase::RequestAsyncContextBase(ani_vm* vm, ani_env* env, AniRequestType type)
    : vm_(vm), env_(env), contextType_(type)
{
    threadId_ = std::this_thread::get_id();
#ifdef EVENTHANDLER_ENABLE
    handler_ = std::make_shared<AppExecFwk::EventHandler>(
        AppExecFwk::EventRunner::GetMainEventRunner());
#endif
}

bool RequestAsyncContextBase::FillInfoFromContext(const ani_object& aniContext)
{
    if (env_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "env_ is nullptr.");
        return false;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env_, aniContext);
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetStageModeContext failed");
        return false;
    }
    stageContext_ = context;
    auto appInfo = context->GetApplicationInfo();
    if (appInfo == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetApplicationInfo failed");
        return false;
    }
    tokenId = appInfo->accessTokenId;
    bundleName = appInfo->bundleName;
    return true;
}

void RequestAsyncContextBase::GetInstanceId()
{
    auto task = [this]() {
        Ace::UIContent* uiContent = GetUIContent(this->stageContext_);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            return;
        }
        this->uiContentFlag = true;
        this->instanceId = uiContent->GetInstanceId();
    };
#ifdef EVENTHANDLER_ENABLE
    if (this->handler_ != nullptr) {
        this->handler_->PostSyncTask(task, "AT:GetInstanceId");
    } else {
        task();
    }
#else
    task();
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d", this->instanceId);
}


bool RequestAsyncContextBase::IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other)
{
    (void) other;
    return false;
}

void RequestAsyncContextBase::CopyResult(const std::shared_ptr<RequestAsyncContextBase> other)
{
    (void) other;
    return;
}

void RequestAsyncContextBase::ProcessFailResult(int32_t code)
{
    result.errorCode = code;
}

void RequestAsyncContextBase::FinishCallback()
{
    if (vm_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "vm_ is nullptr.");
        return;
    }
    bool isSameThread = IsCurrentThread(threadId_);
    ani_env* env = isSameThread ? env_ : GetCurrentEnv(vm_);
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetCurrentEnv failed.");
        return;
    }

    int32_t stsCode = ConvertErrorCode(result.errorCode);
    ani_object error = BusinessErrorAni::CreateError(env, stsCode, GetErrorMessage(stsCode, result.errorMsg));
    ani_object result = WrapResult(env);
    (void)ExecuteAsyncCallback(env, reinterpret_cast<ani_object>(callbackRef), error, result);

    if (!isSameThread && vm_->DetachCurrentThread() != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "DetachCurrentThread failed!");
    }
}

void RequestAsyncContextBase::Clear()
{
    if (vm_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "VM is nullptr.");
        return;
    }
    bool isSameThread = IsCurrentThread(threadId_);
    ani_env* curEnv = isSameThread ? env_ : GetCurrentEnv(vm_);
    if (curEnv == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetCurrentEnv failed.");
        return;
    }

    if (callbackRef != nullptr) {
        curEnv->GlobalReference_Delete(callbackRef);
        callbackRef = nullptr;
    }
}

AniRequestType RequestAsyncContextBase::GetType()
{
    return contextType_;
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContextBase> reqContext)
    :reqContext_(reqContext)
{}

UIExtensionCallback::~UIExtensionCallback()
{}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void UIExtensionCallback::ReleaseHandler(int32_t code)
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
    reqContext_->ProcessFailResult(code);
    controllerInstance_->UpdateQueueData(this->reqContext_);
    controllerInstance_->ExecCallback(this->reqContext_->instanceId);
    reqContext_->FinishCallback();
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode is %{public}d", resultCode);
    reqContext_->ProcessUIExtensionCallback(result);
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void UIExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ReleaseCode is %{public}d", releaseCode);

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void UIExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void UIExtensionCallback::OnDestroy()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

void UIExtensionCallback::SetRequestInstanceControl(std::shared_ptr<RequestInstanceControl> controllerInstance)
{
    this->controllerInstance_ = controllerInstance;
}

void RequestInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InstanceId: %{public}d", asyncContext->instanceId);
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
    asyncContext->StartExtensionAbility(asyncContext);
}

void RequestInstanceControl::UpdateQueueData(
    const std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    if (asyncContext->NoNeedUpdate()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "The queue data does not need to be updated.");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = asyncContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        for (auto& curContext : iter->second) {
            if (curContext != nullptr && curContext->IsSameRequest(asyncContext)) {
                curContext->CopyResult(asyncContext);
            }
        }
    }
}

void RequestInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestAsyncContextBase> asyncContext = nullptr;
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
            if (asyncContext == nullptr) {
                LOGI(ATM_DOMAIN, ATM_TAG, "asyncContext is nullptr.");
                continue;
            }
            isDynamic = asyncContext->CheckDynamicRequest();
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map is empty", id);
            instanceIdMap_.erase(id);
        }
    }
    if (isDynamic) {
        asyncContext->StartExtensionAbility(asyncContext);
    }
}

}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS