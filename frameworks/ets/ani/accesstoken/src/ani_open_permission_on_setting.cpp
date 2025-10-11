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
#include "ani_open_permission_on_setting.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "ani_common.h"
#include "permission_map.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// result code from dialog
constexpr int32_t USER_REJECTED = -1;
constexpr int32_t USER_OPENED = 0;
constexpr int32_t ALREADY_GRANTED = 1;
constexpr int32_t PERM_IS_NOT_DECLARE = 2;
constexpr int32_t PERM_IS_NOT_SUPPORTED = 3;

const std::string PERMISSION_KEY = "ohos.open.setting.permission";
const std::string RESULT_CODE_KEY = "ohos.open.setting.result_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
std::shared_ptr<RequestInstanceControl> g_requestInstanceControl = nullptr;
std::mutex g_requestInstanceControlLock;
}

static std::shared_ptr<RequestInstanceControl> GetRequestInstanceControl()
{
    std::lock_guard<std::mutex> lock(g_requestInstanceControlLock);
    if (g_requestInstanceControl == nullptr) {
        g_requestInstanceControl = std::make_shared<RequestInstanceControl>();
    }
    return g_requestInstanceControl;
}

OpenPermOnSettingAsyncContext::OpenPermOnSettingAsyncContext(ani_vm* vm, ani_env* env)
    : RequestAsyncContextBase(vm, env, REQUEST_PERMISSION_ON_SETTING)
{}

OpenPermOnSettingAsyncContext::~OpenPermOnSettingAsyncContext()
{
    Clear();
}

ani_object OpenPermOnSettingAsyncContext::WrapResult(ani_env* env)
{
    return CreateIntObject(env, this->resultCode);
}

int32_t OpenPermOnSettingAsyncContext::ConvertErrorCode(int32_t errorCode)
{
    int32_t stsCode = STS_OK;

    switch (errorCode) {
        case STS_OK:
            stsCode = STS_OK;
            break;
        case STS_ERROR_PARAM_INVALID:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case STS_ERROR_EXPECTED_PERMISSION_TYPE:
            stsCode = STS_ERROR_EXPECTED_PERMISSION_TYPE;
            break;
        // ability inner error
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Dialog error(%{public}d) stsCode(%{public}d).", errorCode, stsCode);
    return stsCode;
}

void OpenPermOnSettingAsyncContext::ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result)
{
    this->resultCode = result.GetIntParam(RESULT_CODE_KEY, 0);

    switch (this->resultCode) {
        case USER_REJECTED:
        case USER_OPENED:
        case ALREADY_GRANTED:
            this->result_.errorCode = STS_OK;
            break;
        case PERM_IS_NOT_DECLARE:
        case PERM_IS_NOT_SUPPORTED:
            this->result_.errorCode = STS_ERROR_PARAM_INVALID;
            this->result_.errorMsg = "The permission is invalid or not declared in the module.json file.";
            break;
        default:
            this->result_.errorCode = RET_FAILED;
            break;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode=%{public}d, errorCode=%{public}d",
        this->resultCode, this->result_.errorCode);
}

void OpenPermOnSettingAsyncContext::StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(this->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "BundleName: %{public}s, openSettingAbilityName: %{public}s, permission: %{public}s.",
        this->info.grantBundleName.c_str(), this->info.openSettingAbilityName.c_str(), this->permissionName.c_str());
    OHOS::AAFwk::Want want;
    want.SetElementName(this->info.grantBundleName, this->info.openSettingAbilityName);
    want.SetParam(PERMISSION_KEY, this->permissionName);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    CreateUIExtension(want, asyncContext, GetRequestInstanceControl());
}

bool OpenPermOnSettingAsyncContext::IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return false;
    }
    auto ptr = std::static_pointer_cast<OpenPermOnSettingAsyncContext>(other);
    if (permissionName == ptr->permissionName) {
        return true;
    }
    return false;
}

void OpenPermOnSettingAsyncContext::CopyResult(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return;
    }
    auto ptr = std::static_pointer_cast<OpenPermOnSettingAsyncContext>(other);
    this->resultCode = ptr->resultCode;
    this->result_.errorCode = ptr->result_.errorCode;
    this->result_.errorMsg = ptr->result_.errorMsg;
    this->needDynamicRequest_ = false;
}

bool OpenPermOnSettingAsyncContext::CheckDynamicRequest()
{
    if (!this->needDynamicRequest_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission extension.");
        FinishCallback();
        return false;
    }
    return true;
}

void OpenPermOnSettingAsyncContext::ProcessFailResult(int32_t code)
{
    if (code == -1) {
        this->result_.errorCode = code;
    }
}

bool OpenPermOnSettingAsyncContext::NoNeedUpdate()
{
    return false;
}

static bool ParseOpenPermissionOnSetting(ani_env* env, ani_object& aniContext, ani_string& aniPermission,
    ani_object callback, std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext)
{
    if (!asyncContext->FillInfoFromContext(aniContext)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    asyncContext->permissionName = ParseAniString(env, aniPermission);
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef_)) {
        return false;
    }
    return true;
}

static bool CheckManualSettingPerm(ani_env* env, const std::string& permissionName, ani_object& error)
{
    PermissionBriefDef permissionBriefDef;
    if (!GetPermissionBriefDef(permissionName, permissionBriefDef)) {
        error = BusinessErrorAni::CreateError(env, STS_ERROR_PARAM_INVALID,
            GetErrorMessage(STS_ERROR_PARAM_INVALID, "The permission is invalid."));
        return true;
    }

    if (permissionBriefDef.grantMode != MANUAL_SETTINGS) {
        error = BusinessErrorAni::CreateError(env, STS_ERROR_EXPECTED_PERMISSION_TYPE,
            GetErrorMessage(STS_ERROR_EXPECTED_PERMISSION_TYPE, "The permission is not a manual_settings permission."));
        return true;
    }
    return false;
}

void OpenPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_string aniPermission, ani_object callback)
{
    if (env == nullptr || aniPermission == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or permission or callback is null.");
        return;
    }

    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetVM, error=%{public}u.", status);
        return;
    }

    std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext =
        std::make_shared<OpenPermOnSettingAsyncContext>(vm, env);
    if (!ParseOpenPermissionOnSetting(env, aniContext, aniPermission, callback, asyncContext)) {
        return;
    }
    ani_ref undefRef = nullptr;
    env->GetUndefined(&undefRef);
    ani_object result = reinterpret_cast<ani_object>(undefRef);
    ani_object error;

    if (CheckManualSettingPerm(env, asyncContext->permissionName, error)) {
        (void)ExecuteAsyncCallback(env, callback, error, result);
        return;
    }

    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG, "The context tokenID %{public}d is not same with selfTokenID %{public}d.",
            asyncContext->tokenId, selfTokenID);
        error =
            BusinessErrorAni::CreateError(env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID,
            "The specified context does not belong to the current application."));
        (void)ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    asyncContext->GetInstanceId();
    GetRequestInstanceControl()->AddCallbackByInstanceId(asyncContext);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog.");

    if (asyncContext->result_.errorCode != RET_SUCCESS) {
        asyncContext->FinishCallback();
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS