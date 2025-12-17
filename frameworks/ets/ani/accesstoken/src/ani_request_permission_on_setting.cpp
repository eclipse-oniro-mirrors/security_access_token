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
#include "accesstoken_common_log.h"
#include "ani_common.h"
#include "hisysevent.h"
#include "permission_map.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t REQUEST_ALREADY_EXIST = 1;
constexpr int32_t PERM_NOT_BELONG_TO_SAME_GROUP = 2;
constexpr int32_t PERM_IS_NOT_DECLARE = 3;
constexpr int32_t ALL_PERM_GRANTED = 4;
constexpr int32_t PERM_NOT_REVOKE_BY_USER = 5;
const std::string PERMISSION_SETTING_KEY = "ohos.user.setting.permission";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string PERMISSION_RESULT_KEY = "ohos.user.setting.permission.result";
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

RequestPermOnSettingAsyncContext::RequestPermOnSettingAsyncContext(ani_vm* vm, ani_env* env)
    : RequestAsyncContextBase(vm, env, REQUEST_PERMISSION_ON_SETTING)
{}

RequestPermOnSettingAsyncContext::~RequestPermOnSettingAsyncContext()
{
    Clear();
}

static void StateToEnumIndex(int32_t state, ani_size& enumIndex)
{
    if (state == 0) {
        enumIndex = 1;
    } else {
        enumIndex = 0;
    }
}

ani_object RequestPermOnSettingAsyncContext::WrapResult(ani_env* env)
{
    ani_class arrayCls = nullptr;
    if (env->FindClass("escompat.Array", &arrayCls) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass name escompat.Array!");
        return nullptr;
    }

    ani_method arrayCtor;
    if (env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass <ctor>!");
        return nullptr;
    }

    ani_object arrayObj;
    if (env->Object_New(arrayCls, arrayCtor, &arrayObj, static_cast<int32_t>(this->stateList_.size()))
        != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object new failed!");
        return nullptr;
    }

    const char* enumDescriptor = "@ohos.abilityAccessCtrl.abilityAccessCtrl.GrantStatus";
    ani_enum enumType;
    if (env->FindEnum(enumDescriptor, &enumType) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass name %{public}s!", enumDescriptor);
        return nullptr;
    }

    ani_size index = 0;
    for (const auto& state: this->stateList_) {
        ani_enum_item enumItem;
        ani_size enumIndex = 0;
        StateToEnumIndex(state, enumIndex);
        if (env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetEnumItemByIndex value %{public}u!", state);
            break;
        }
        ani_status status;
        if ((status = env->Object_CallMethodByName_Void(
            arrayObj, "$_set", "iC{std.core.Object}:", index, enumItem)) != ANI_OK) {
            break;
        }
        index++;
    }

    return arrayObj;
}

int32_t RequestPermOnSettingAsyncContext::ConvertErrorCode(int32_t errorCode)
{
    int32_t stsCode = STS_OK;
    switch (errorCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case REQUEST_ALREADY_EXIST:
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Dialog error(%{public}d) stsCode(%{public}d).", errorCode, stsCode);
    return stsCode;
}

void RequestPermOnSettingAsyncContext::ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result)
{
    this->result_.errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->stateList_ = result.GetIntArrayParam(PERMISSION_RESULT_KEY);
}

static std::string JoinStrings(const std::vector<std::string>& permissionList)
{
    std::ostringstream perms;
    perms << "permList:[";
    for (size_t i = 0; i < permissionList.size(); ++i) {
        perms << permissionList[i];
        if (i != permissionList.size() - 1) {
            perms << ", ";
        }
    }
    perms << "]";
    return perms.str();
}

void RequestPermOnSettingAsyncContext::StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(this->info);
    std::string perms = JoinStrings(this->permissionList);
    LOGI(ATM_DOMAIN, ATM_TAG, "BundleName: %{public}s, permStateAbilityName: %{public}s, permissionList: %{public}s.",
        this->info.grantBundleName.c_str(), this->info.permStateAbilityName.c_str(), perms.c_str());
    OHOS::AAFwk::Want want;
    want.SetElementName(this->info.grantBundleName, this->info.permStateAbilityName);
    want.SetParam(PERMISSION_SETTING_KEY, this->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    CreateUIExtension(want, asyncContext, GetRequestInstanceControl());
}

static bool CheckPermList(std::vector<std::string> permList, std::vector<std::string> tmpPermList)
{
    if (permList.size() != tmpPermList.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm list size not equal, CurrentPermList size: %{public}zu.", tmpPermList.size());
        return false;
    }

    for (const auto& item : permList) {
        auto iter = std::find_if(tmpPermList.begin(), tmpPermList.end(), [item](const std::string& perm) {
            return item == perm;
        });
        if (iter == tmpPermList.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Different permission lists.");
            return false;
        }
    }
    return true;
}

bool RequestPermOnSettingAsyncContext::IsSameRequest(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return false;
    }
    auto ptr = std::static_pointer_cast<RequestPermOnSettingAsyncContext>(other);
    return CheckPermList(permissionList, ptr->permissionList);
}

void RequestPermOnSettingAsyncContext::CopyResult(const std::shared_ptr<RequestAsyncContextBase> other)
{
    if (other == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "other is nullptr.");
        return;
    }
    auto ptr = std::static_pointer_cast<RequestPermOnSettingAsyncContext>(other);
    this->result_.errorCode = ptr->result_.errorCode;
    this->stateList_ = ptr->stateList_;
    this->needDynamicRequest_ = false;
}

bool RequestPermOnSettingAsyncContext::CheckDynamicRequest()
{
    if (!this->needDynamicRequest_) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission extension");
        FinishCallback();
        return false;
    }
    return true;
}

void RequestPermOnSettingAsyncContext::ProcessFailResult(int32_t code)
{
    if (code == -1) {
        this->result_.errorCode = code;
    }
}

bool RequestPermOnSettingAsyncContext::NoNeedUpdate()
{
    if (result_.errorCode != RET_SUCCESS) {
        return true;
    }
    for (int32_t item : this->stateList_) {
        if (item != PERMISSION_GRANTED) {
            return true;
        }
    }
    return false;
}

static bool ParseRequestPermissionOnSetting(ani_env* env, ani_object& aniContext, ani_array& aniPermissionList,
    ani_object callback, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    if (!asyncContext->FillInfoFromContext(aniContext)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    asyncContext->permissionList = ParseAniStringVector(env, aniPermissionList);
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef_)) {
        return false;
    }
    return true;
}

static bool CheckManualSettingPerm(const std::vector<std::string>& permissionList, std::string& permission)
{
    for (const auto& perm : permissionList) {
        PermissionBriefDef permissionBriefDef;
        if (GetPermissionBriefDef(perm, permissionBriefDef)) {
            if (permissionBriefDef.grantMode == MANUAL_SETTINGS) {
                permission = perm;
                return true;
            }
        }
    }
    return false;
}

void RequestPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_array permissionList, ani_object callback)
{
    if (env == nullptr || permissionList == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or permissionList or callback is null.");
        return;
    }
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetVM, error=%{public}u.", status);
        return;
    }

    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>(vm, env);
    if (!ParseRequestPermissionOnSetting(env, aniContext, permissionList, callback, asyncContext)) {
        return;
    }
    ani_ref undefRef = nullptr;
    env->GetUndefined(&undefRef);
    ani_object result = reinterpret_cast<ani_object>(undefRef);
    std::string permission;
    if (CheckManualSettingPerm(asyncContext->permissionList, permission)) {
        ani_object error = BusinessErrorAni::CreateError(env, STS_ERROR_EXPECTED_PERMISSION_TYPE,
            GetErrorMessage(STS_ERROR_EXPECTED_PERMISSION_TYPE,
            "The specified permission " + permission + " cannot be requested from the user."));
        ExecuteAsyncCallback(env, callback, error, result);
        return;
    }

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
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog.");
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName,
        "UIEXTENSION_FLAG", true, "SCENE_CODE", static_cast<int32_t>(asyncContext->contextType_),
        "TOKENID", asyncContext->tokenId, "EXTRA_INFO", TransPermissionsToString(asyncContext->permissionList));
    if (asyncContext->result_.errorCode != RET_SUCCESS) {
        asyncContext->FinishCallback();
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS