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
#include "ani_request_permission_on_setting.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<RequestPermOnSettingAsyncContext>>>
    RequestOnSettingAsyncInstanceControl::instanceIdMap_;
std::mutex RequestOnSettingAsyncInstanceControl::instanceIdMutex_;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniRequestPermission" };
constexpr int32_t REQUEST_REALDY_EXIST = 1;
constexpr int32_t PERM_NOT_BELONG_TO_SAME_GROUP = 2;
constexpr int32_t PERM_IS_NOT_DECLARE = 3;
constexpr int32_t ALL_PERM_GRANTED = 4;
constexpr int32_t PERM_NOT_REVOKE_BY_USER = 5;
const std::string PERMISSION_SETTING_KEY = "ohos.user.setting.permission";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string PERMISSION_RESULT_KEY = "ohos.user.setting.permission.result";
}
RequestPermOnSettingAsyncContext::~RequestPermOnSettingAsyncContext()
{
    if (vm == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "VM is nullptr.");
        return;
    }
    bool isSameThread = IsCurrentThread(threadId);
    ani_env* curEnv = isSameThread ? env : GetCurrentEnv(vm);
    if (curEnv == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetCurrentEnv failed.");
        return;
    }

    if (callbackRef != nullptr) {
        curEnv->GlobalReference_Delete(callbackRef);
        callbackRef = nullptr;
    }
}

static ani_status GetContext(
    ani_env* env, const ani_object& aniContext, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    if (context == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetStageModeContext failed");
        return ANI_ERROR;
    }
    asyncContext->abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (asyncContext->abilityContext != nullptr) {
        auto abilityInfo = asyncContext->abilityContext->GetApplicationInfo();
        if (abilityInfo == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetApplicationInfo failed");
            return ANI_ERROR;
        }
        asyncContext->uiAbilityFlag = true;
        asyncContext->tokenId = abilityInfo->accessTokenId;
    } else {
        asyncContext->uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context);
        if (asyncContext->uiExtensionContext == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertTo UIExtensionContext failed");
            return ANI_ERROR;
        }
        auto uiExtensionInfo = asyncContext->uiExtensionContext->GetApplicationInfo();
        if (uiExtensionInfo == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetApplicationInfo failed");
            return ANI_ERROR;
        }
        asyncContext->tokenId = uiExtensionInfo->accessTokenId;
    }
    return ANI_OK;
}

static bool ParseRequestPermissionOnSetting(ani_env* env, ani_object& aniContext, ani_array_ref& permissionList,
    ani_object callback, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetVM failed, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }
    asyncContext->vm = vm;
    asyncContext->env = env;
    asyncContext->callback = callback;
    asyncContext->threadId = std::this_thread::get_id();

    if (GetContext(env, aniContext, asyncContext) != ANI_OK) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    if (!AniParaseArrayString(env, nullptr, permissionList, asyncContext->permissionList)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionList", "Array<string>"));
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

static void StateToEnumIndex(int32_t state, ani_size& enumIndex)
{
    if (state == 0) {
        enumIndex = 1;
    } else {
        enumIndex = 0;
    }
}

static ani_object ReturnResult(ani_env* env, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    ani_class arrayCls = nullptr;
    if (env->FindClass("Lescompat/Array;", &arrayCls) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass name Lescompat/Array failed!");
        return nullptr;
    }

    ani_method arrayCtor;
    if (env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass <ctor> failed!");
        return nullptr;
    }

    ani_object arrayObj;
    if (env->Object_New(arrayCls, arrayCtor, &arrayObj, asyncContext->stateList.size()) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object new failed!");
        return nullptr;
    }

    const char* enumDescriptor = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/GrantStatus;";
    ani_enum enumType;
    if (env->FindEnum(enumDescriptor, &enumType) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass name %{public}s failed!", enumDescriptor);
        return nullptr;
    }

    ani_size index = 0;
    for (const auto& state: asyncContext->stateList) {
        ani_enum_item enumItem;
        ani_size enumIndex = 0;
        StateToEnumIndex(state, enumIndex);
        if (env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem) != ANI_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetEnumItemByIndex value %{public}u failed!", state);
            break;
        }

        if (env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, enumItem) != ANI_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Object_CallMethodByName_Void $_set failed!");
            break;
        }
        index++;
    }

    return arrayObj;
}

static int32_t TransferToStsErrorCode(int32_t errorCode)
{
    int32_t stsCode = STS_OK;
    switch (errorCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case REQUEST_REALDY_EXIST:
            stsCode = STS_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case PERM_NOT_BELONG_TO_SAME_GROUP:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case PERM_IS_NOT_DECLARE:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case ALL_PERM_GRANTED:
            stsCode = STS_ERROR_ALL_PERM_GRANTED;
            break;
        case PERM_NOT_REVOKE_BY_USER:
            stsCode = STS_ERROR_PERM_NOT_REVOKE_BY_USER;
            break;
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Dialog error(%{public}d) stsCode(%{public}d).", errorCode, stsCode);
    return stsCode;
}

PermissonOnSettingUICallback::PermissonOnSettingUICallback(
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

PermissonOnSettingUICallback::~PermissonOnSettingUICallback()
{}

void PermissonOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

static void PermissionResultsCallbackUI(
    const std::vector<int32_t> stateList, std::shared_ptr<RequestPermOnSettingAsyncContext>& data)
{
    bool isSameThread = IsCurrentThread(data->threadId);
    ani_env* env = isSameThread ? data->env : GetCurrentEnv(data->vm);
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetCurrentEnv failed.");
        return;
    }

    int32_t stsCode = TransferToStsErrorCode(data->result.errorCode);
    ani_object error = BusinessErrorAni::CreateError(env, stsCode, GetErrorMessage(stsCode, data->result.errorMsg));
    ani_object result = ReturnResult(env, data);
    ExecuteAsyncCallback(env, reinterpret_cast<ani_object>(data->callbackRef), error, result);

    if (!isSameThread && data->vm->DetachCurrentThread() != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "DetachCurrentThread failed!");
    }
}

static void CloseSettingModalUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
    int32_t sessionId)
{
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }
        uiContent->CloseModalUIExtension(sessionId);
        ACCESSTOKEN_LOG_INFO(LABEL, "Close end, sessionId: %{public}d", sessionId);
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

void PermissonOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(this->reqContext_->lockReleaseFlag);
        if (this->reqContext_->releaseFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseSettingModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    if (code == -1) {
        this->reqContext_->result.errorCode = code;
    }
    RequestOnSettingAsyncInstanceControl::UpdateQueueData(this->reqContext_);
    RequestOnSettingAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    PermissionResultsCallbackUI(this->reqContext_->stateList, this->reqContext_);
}

/*
    * when UIExtensionAbility use terminateSelfWithResult
    */
void PermissonOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->result.errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->stateList = result.GetIntArrayParam(PERMISSION_RESULT_KEY);
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d,  errorCodeis %{public}d, listSize=%{public}zu.",
        resultCode, this->reqContext_->result.errorCode, this->reqContext_->stateList.size());
    ReleaseHandler(0);
}

/*
    * when UIExtensionAbility send message to UIExtensionComponent
    */
void PermissonOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called!");
}

/*
    * when UIExtensionAbility disconnect or use terminate or process die
    * releaseCode is 0 when process normal exit
    */
void PermissonOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseCode is %{public}d", releaseCode);

    ReleaseHandler(-1);
}

/*
    * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
    */
void PermissonOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

/*
    * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
    * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
    */
void PermissonOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Connect to UIExtensionAbility successfully.");
}

/*
    * when UIExtensionComponent destructed
    */
void PermissonOnSettingUICallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

static void CreateSettingUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<PermissonOnSettingUICallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get ui content!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }

        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        ACCESSTOKEN_LOG_INFO(LABEL, "Create end, sessionId: %{public}d, tokenId: %{public}d.",
            sessionId, asyncContext->tokenId);
        if (sessionId == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create component, sessionId is 0.");
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
    const OHOS::AAFwk::Want &want, std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    auto uiExtCallback = std::make_shared<PermissonOnSettingUICallback>(asyncContext);
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

    CreateSettingUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
}

static void StartUIExtension(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName: %{public}s, permStateAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.permStateAbilityName.c_str());
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.permStateAbilityName);
    want.SetParam(PERMISSION_SETTING_KEY, asyncContext->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    CreateUIExtension(want, asyncContext);
}

static void GetInstanceId(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Instance id: %{public}d", asyncContext->instanceId);
}

void RequestOnSettingAsyncInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "InstanceId: %{public}d", asyncContext->instanceId);
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(asyncContext->instanceId);
        // id is existed mean a pop window is showing, add context to waiting queue
        if (iter != instanceIdMap_.end()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "InstanceId: %{public}d has existed.", asyncContext->instanceId);
            instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
            return;
        }
        // make sure id is in map to indicate a pop-up window is showing
        instanceIdMap_[asyncContext->instanceId] = {};
    }
    StartUIExtension(asyncContext);
}

bool static CheckPermList(std::vector<std::string> permList, std::vector<std::string> tmpPermList)
{
    if (permList.size() != tmpPermList.size()) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Perm list size not equal, CurrentPermList size: %{public}zu.", tmpPermList.size());
        return false;
    }

    for (const auto& item : permList) {
        auto iter = std::find_if(tmpPermList.begin(), tmpPermList.end(), [item](const std::string& perm) {
            return item == perm;
        });
        if (iter == tmpPermList.end()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Different permission lists.");
            return false;
        }
    }
    return true;
}

void RequestOnSettingAsyncInstanceControl::UpdateQueueData(
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    if (reqContext->result.errorCode != RET_SUCCESS) {
        ACCESSTOKEN_LOG_INFO(LABEL, "The queue data does not need to be updated.");
        return;
    }
    for (const int32_t item : reqContext->stateList) {
        if (item != PERMISSION_GRANTED) {
            ACCESSTOKEN_LOG_INFO(LABEL, "The queue data does not need to be updated");
            return;
        }
    }

    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = reqContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d not existed.", id);
            return;
        }
        std::vector<std::string> permList = reqContext->permissionList;
        ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
        for (auto& asyncContext : iter->second) {
            std::vector<std::string> tmpPermList = asyncContext->permissionList;
            if (CheckPermList(permList, tmpPermList)) {
                asyncContext->result.errorCode = reqContext->result.errorCode;
                asyncContext->stateList = reqContext->stateList;
                asyncContext->isDynamic = false;
            }
        }
    }
}

void RequestOnSettingAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext = nullptr;
    bool isDynamic = false;
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d not existed.", id);
            return;
        }
        while (!iter->second.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
            asyncContext = iter->second[0];
            iter->second.erase(iter->second.begin());
            CheckDynamicRequest(asyncContext, isDynamic);
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d, map is empty", id);
            instanceIdMap_.erase(id);
        }
    }
    if (isDynamic) {
        StartUIExtension(asyncContext);
    }
}

void RequestOnSettingAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext, bool& isDynamic)
{
    isDynamic = asyncContext->isDynamic;
    if (!isDynamic) {
        ACCESSTOKEN_LOG_INFO(LABEL, "It does not need to request permission exsion");
        PermissionResultsCallbackUI(asyncContext->stateList, asyncContext);
        return;
    }
}

void RequestPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_array_ref permissionList, ani_object callback)
{
    if (env == nullptr || permissionList == nullptr || callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env or permissionList or callback is null.");
        return;
    }

    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>();
    if (!ParseRequestPermissionOnSetting(env, aniContext, permissionList, callback, asyncContext)) {
        return;
    }

    ani_ref nullRef = nullptr;
    env->GetNull(&nullRef);
    ani_object result = reinterpret_cast<ani_object>(nullRef);
    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "The context tokenID %{public}d is not same with selfTokenID %{public}d.",
            asyncContext->tokenId, selfTokenID);
        ani_object error =
            BusinessErrorAni::CreateError(env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID,
            "The specified context does not belong to the current application."));
        ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    GetInstanceId(asyncContext);
    RequestOnSettingAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
    ACCESSTOKEN_LOG_INFO(LABEL, "Start to pop ui extension dialog");

    if (asyncContext->result.errorCode != RET_SUCCESS) {
        int32_t stsCode = TransferToStsErrorCode(asyncContext->result.errorCode);
        ani_object error = BusinessErrorAni::CreateError(
            env, stsCode, GetErrorMessage(stsCode, asyncContext->result.errorMsg));
        ExecuteAsyncCallback(env, callback, error, result);
        ACCESSTOKEN_LOG_WARN(LABEL, "Failed to pop uiextension dialog.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS