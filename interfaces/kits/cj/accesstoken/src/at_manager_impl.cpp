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

#include "at_manager_impl.h"
#include "ability_access_ctrl_common.h"
#include "ability.h"
#include "ability_manager_client.h"
#include "access_token.h"
#include "access_token_error.h"
#include "macro.h"
#include "parameter.h"
#include "token_setproc.h"
#include "want.h"

using namespace OHOS::FFI;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace CJSystemapi {

std::mutex g_lockForPermStateChangeRegisters;
std::vector<RegisterPermStateChangeInfo*> g_permStateChangeRegisters;
std::mutex g_lockCache;
std::map<std::string, GrantStatusCache> g_cache;
static PermissionParamCache g_paramCache;
std::mutex g_lockForPermRequestCallbacks;
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";

const std::string GRANT_ABILITY_BUNDLE_NAME = "com.ohos.permissionmanager";
const std::string GRANT_ABILITY_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string STATE_KEY = "ohos.user.grant.permission.state";
const std::string TOKEN_KEY = "ohos.ability.params.token";
const std::string CALLBACK_KEY = "ohos.ability.params.callback";
const std::string RESULT_KEY = "ohos.user.grant.permission.result";

const std::string WINDOW_RECTANGLE_LEFT_KEY = "ohos.ability.params.request.left";
const std::string WINDOW_RECTANGLE_TOP_KEY = "ohos.ability.params.request.top";
const std::string WINDOW_RECTANGLE_HEIGHT_KEY = "ohos.ability.params.request.height";
const std::string WINDOW_RECTANGLE_WIDTH_KEY = "ohos.ability.params.request.width";
const std::string REQUEST_TOKEN_KEY = "ohos.ability.params.request.token";

static int32_t g_curRequestCode = 0;

static constexpr int32_t VALUE_MAX_LEN = 32;
static constexpr int32_t MAX_WAIT_TIME = 1000;

extern "C" {
static int32_t GetCjErrorCode(uint32_t errCode)
{
    int32_t cjCode;
    switch (errCode) {
        case OHOS::Security::AccessToken::ERR_PERMISSION_DENIED:
            cjCode = CJ_ERROR_PERMISSION_DENIED;
            break;
        case ERR_NOT_SYSTEM_APP:
            cjCode = CJ_ERROR_NOT_SYSTEM_APP;
            break;
        case ERR_PARAM_INVALID:
            cjCode = CJ_ERROR_PARAM_INVALID;
            break;
        case ERR_TOKENID_NOT_EXIST:
            cjCode = CJ_ERROR_TOKENID_NOT_EXIST;
            break;
        case ERR_PERMISSION_NOT_EXIST:
            cjCode = CJ_ERROR_PERMISSION_NOT_EXIST;
            break;
        case ERR_INTERFACE_NOT_USED_TOGETHER:
        case ERR_CALLBACK_ALREADY_EXIST:
            cjCode = CJ_ERROR_NOT_USE_TOGETHER;
            break;
        case ERR_CALLBACKS_EXCEED_LIMITATION:
            cjCode = CJ_ERROR_REGISTERS_EXCEED_LIMITATION;
            break;
        case ERR_IDENTITY_CHECK_FAILED:
            cjCode = CJ_ERROR_PERMISSION_OPERATION_NOT_ALLOWED;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERROR_IPC_REQUEST_FAIL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
            cjCode = CJ_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_MALLOC_FAILED:
            cjCode = CJ_ERROR_OUT_OF_MEMORY;
            break;
        default:
            cjCode = CJ_ERROR_INNER;
            break;
    }
    LOGI("GetCjErrorCode nativeCode(%{public}d) cjCode(%{public}d).", errCode, cjCode);
    return cjCode;
}

static bool IsCurrentThread(std::thread::id threadId)
{
    std::thread::id currentThread = std::this_thread::get_id();
    if (threadId != currentThread) {
        LOGE("Ref can not be compared, different threadId!");
        return false;
    }
    return true;
}

static bool CompareCallbackRef(int64_t subscriberRef, int64_t unsubscriberRef, std::thread::id threadId)
{
    if (!IsCurrentThread(threadId)) {
        return false;
    }
    return subscriberRef == unsubscriberRef;
}

static std::vector<std::string> CArrStringToVector(const CArrString& cArr)
{
    LOGI("ACCESS_CTRL_TEST:: CArrStringToVector start");
    std::vector<std::string> ret;
    for (int64_t i = 0; i < cArr.size; i++) {
        ret.emplace_back(std::string(cArr.head[i]));
    }
    LOGI("ACCESS_CTRL_TEST:: CArrStringToVector end");
    return ret;
}

char* MallocCString(const std::string& stdString)
{
    if (stdString.empty()) {
        return nullptr;
    }
    auto length = stdString.length() + 1;
    char* ret = static_cast<char*>(malloc(sizeof(char) * length));
    if (ret == nullptr) {
        LOGE("MallocCString: malloc failed!");
        return nullptr;
    }
    return std::char_traits<char>::copy(ret, stdString.c_str(), length);
}

static char** VectorToCArrString(const std::vector<std::string>& vec)
{
    char** result = static_cast<char**>(malloc(sizeof(char*) * vec.size()));
    if (result == nullptr) {
        LOGE("VectorToCArrString: malloc failed!");
        return nullptr;
    }
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = MallocCString(vec[i]);
    }
    return result;
}

static int32_t* VectorToCArrInt32(const std::vector<int32_t>& vec)
{
    int32_t* result = static_cast<int32_t*>(malloc(sizeof(int32_t) * vec.size()));
    if (result == nullptr) {
        LOGE("VectorToCArrInt32: malloc failed!");
        return nullptr;
    }
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = vec[i];
    }
    return result;
}

static bool* VectorToCArrBool(const std::vector<bool>& vec)
{
    bool* result = static_cast<bool*>(malloc(sizeof(bool) * vec.size()));
    if (result == nullptr) {
        LOGE("VectorToCArrBool: malloc failed!");
        return nullptr;
    }
    for (size_t i = 0; i < vec.size(); i++) {
        result[i] = vec[i];
    }
    return result;
}

int32_t AtManagerImpl::VerifyAccessTokenSync(unsigned int tokenID, const char* cPermissionName)
{
    LOGI("ACCESS_CTRL_TEST::AtManagerImpl::VerifyAccessTokenSync START");
    static AccessTokenID selgTokenId = GetSelfTokenID();
    if (tokenID != selgTokenId) {
        auto result = AccessTokenKit::VerifyAccessToken(tokenID, cPermissionName);
        LOGI("ACCESS_CTRL_TEST::AtManagerImpl::VerifyAccessTokenSync end.");
        return result;
    }

    int32_t result;
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(cPermissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue();
        if (currPara != iter->second.paramValue) {
            result = AccessTokenKit::VerifyAccessToken(
                tokenID, cPermissionName);
            iter->second.status = result;
            iter->second.paramValue = currPara;
            LOGI("Param changed currPara %{public}s", currPara.c_str());
        } else {
            result = iter->second.status;
        }
    } else {
        result = AccessTokenKit::VerifyAccessToken(tokenID, cPermissionName);
        g_cache[cPermissionName].status = result;
        g_cache[cPermissionName].paramValue = GetPermParamValue();
        LOGI("g_cacheParam set %{public}s", g_cache[cPermissionName].paramValue.c_str());
    }
    LOGI("ACCESS_CTRL_TEST::AtManagerImpl::VerifyAccessTokenSync end cache.");
    return result;
}

int32_t AtManagerImpl::GrantUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags)
{
    LOGI("ACCESS_CTRL_TEST::AtManagerImpl::GrantUserGrantedPermission START");

    PermissionDef permissionDef;
    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    int32_t result = AccessTokenKit::GetDefPermission(cPermissionName, permissionDef);
    if (result != AT_PERM_OPERA_SUCC) {
        LOGE("ACCESS_CTRL_TEST::AtManagerImpl::GrantUserGrantedPermission failed");
        return result;
    }

    LOGI("permissionName = %{public}s, grantmode = %{public}d.",
        cPermissionName, permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        result = AccessTokenKit::GrantPermission(tokenID, cPermissionName, permissionFlags);
    } else {
        result = CjErrorCode::CJ_ERROR_PERMISSION_NOT_EXIST;
    }
    LOGI("tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d, grant result = %{public}d.", tokenID,
        cPermissionName, permissionFlags, result);
    return result;
}

int32_t AtManagerImpl::RevokeUserGrantedPermission(unsigned int tokenID, const char* cPermissionName,
    unsigned int permissionFlags)
{
    LOGI("ACCESS_CTRL_TEST::AtManagerImpl::RevokeUserGrantedPermission START");

    PermissionDef permissionDef;

    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    int32_t result = AccessTokenKit::GetDefPermission(cPermissionName, permissionDef);
    if (result != AT_PERM_OPERA_SUCC) {
        LOGE("ACCESS_CTRL_TEST::AtManagerImpl::RevokeUserGrantedPermission failed");
        return result;
    }

    LOGI("permissionName = %{public}s, grantmode = %{public}d.", cPermissionName, permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        result = AccessTokenKit::RevokePermission(tokenID, cPermissionName, permissionFlags);
    } else {
        result = CjErrorCode::CJ_ERROR_PERMISSION_NOT_EXIST;
    }
    LOGI("tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d, revoke result = %{public}d.",
        tokenID, cPermissionName, permissionFlags, result);
    return result;
}

int32_t AtManagerImpl::RegisterPermStateChangeCallback(
    const char* cType,
    CArrUI32 cTokenIDList,
    CArrString cPermissionList,
    int64_t callbackRef)
{
    RegisterPermStateChangeInfo* registerPermStateChangeInfo =
        new (std::nothrow) RegisterPermStateChangeInfo();
    if (registerPermStateChangeInfo == nullptr) {
        LOGE("insufficient memory for subscribeCBInfo!");
        return CJ_ERROR_OUT_OF_MEMORY;
    }
    std::unique_ptr<RegisterPermStateChangeInfo> callbackPtr {registerPermStateChangeInfo};
    // ParseInputToRegister
    auto ret = FillPermStateChangeInfo(cType, cTokenIDList, cPermissionList, callbackRef,
        *registerPermStateChangeInfo);
    if (ret != CJ_OK) {
        LOGE("FillPermStateChangeInfo failed");
        return ret;
    }
    if (IsExistRegister(registerPermStateChangeInfo)) {
        LOGE("Subscribe failed. The current subscriber has been existed");
        return CJ_ERROR_PARAM_INVALID;
    }
    int32_t result = AccessTokenKit::RegisterPermStateChangeCallback(registerPermStateChangeInfo->subscriber);
    if (result != CJ_OK) {
        LOGE("RegisterPermStateChangeCallback failed");
        registerPermStateChangeInfo->errCode = result;
        return GetCjErrorCode(result);
    }
    {
        std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
        g_permStateChangeRegisters.emplace_back(registerPermStateChangeInfo);
        LOGE("add g_PermStateChangeRegisters.size = %{public}zu",
            g_permStateChangeRegisters.size());
    }
    callbackPtr.release();
    return result;
}

int32_t AtManagerImpl::UnregisterPermStateChangeCallback(
    const char* cType,
    CArrUI32 cTokenIDList,
    CArrString cPermissionList,
    int64_t callbackRef)
{
    UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo =
        new (std::nothrow) UnregisterPermStateChangeInfo();
    if (unregisterPermStateChangeInfo == nullptr) {
        LOGE("insufficient memory for subscribeCBInfo!");
        return CJ_ERROR_OUT_OF_MEMORY;
    }
    std::unique_ptr<UnregisterPermStateChangeInfo> callbackPtr {unregisterPermStateChangeInfo};
    // ParseInputToUnregister
    auto ret = FillUnregisterPermStateChangeInfo(cType, cTokenIDList, cPermissionList, callbackRef,
        *unregisterPermStateChangeInfo);
    if (ret != CJ_OK) {
        LOGE("FillPermStateChangeInfo failed");
        return ret;
    }
    std::vector<RegisterPermStateChangeInfo*> batchPermStateChangeRegisters;

    if (!FindAndGetSubscriberInVector(unregisterPermStateChangeInfo, batchPermStateChangeRegisters)) {
        LOGE("Unsubscribe failed. The current subscriber does not exist");
        return CjErrorCode::CJ_ERROR_PARAM_INVALID;
    }

    for (const auto& item : batchPermStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        int32_t result = AccessTokenKit::UnRegisterPermStateChangeCallback(item->subscriber);
        if (result == RET_SUCCESS) {
            DeleteRegisterFromVector(scopeInfo, item->callbackRef);
        } else {
            LOGE("Batch UnregisterPermActiveChangeCompleted failed");
            return GetCjErrorCode(result);
        }
    }
    return CJ_OK;
}

static void fillRequestResult(CPermissionRequestResult& retData, std::vector<std::string> permissionList,
    std::vector<int32_t> permissionsState, std::vector<bool> dialogShownResults)
{
    retData.permissions.size = static_cast<int64_t>(permissionList.size());
    retData.permissions.head = VectorToCArrString(permissionList);
    if (retData.permissions.head == nullptr) {
        return;
    }
    retData.authResults.size = static_cast<int64_t>(permissionsState.size());
    retData.authResults.head = VectorToCArrInt32(permissionsState);

    retData.dialogShownResults.size = static_cast<int64_t>(dialogShownResults.size());
    retData.dialogShownResults.head = VectorToCArrBool(dialogShownResults);
}

static void UpdateGrantPermissionResultOnly(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, const std::vector<int>& permissionsState, std::vector<int>& newGrantResults)
{
    uint32_t size = permissions.size();

    for (uint32_t i = 0; i < size; i++) {
        int result = permissionsState[i] == DYNAMIC_OPER ? grantResults[i] : permissionsState[i];
        newGrantResults.emplace_back(result);
    }
}

void AuthorizationResult::GrantResultsCallback(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults)
{
    LOGI("AuthorizationResult::GrantResultsCallback");
    RetDataCPermissionRequestResult ret{};
    fillRequestResult(ret.data, permissions, grantResults, this->data_->dialogShownResults);
    ret.code = AT_PERM_OPERA_SUCC;
    data_->callbackRef(ret);
}

static int32_t StartServiceExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        return CjErrorCode::CJ_ERROR_INNER;
    }

    AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantServiceAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(TOKEN_KEY, asyncContext->abilityContext->GetToken());
    want.SetParam(CALLBACK_KEY, remoteObject);

    int32_t left;
    int32_t top;
    int32_t width;
    int32_t height;
    asyncContext->abilityContext->GetWindowRect(left, top, width, height);
    want.SetParam(WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(WINDOW_RECTANGLE_HEIGHT_KEY, height);
    want.SetParam(REQUEST_TOKEN_KEY, asyncContext->abilityContext->GetToken());
    int32_t err = AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, asyncContext->abilityContext->GetToken());
    LOGI("End calling StartExtension. ret=%{public}d", err);
    std::lock_guard<std::mutex> lock(g_lockForPermRequestCallbacks);
    g_curRequestCode = (g_curRequestCode == INT_MAX) ? 0 : (g_curRequestCode + 1);
    return err;
}

bool AtManagerImpl::ParseRequestPermissionFromUser(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
    const std::function<void(RetDataCPermissionRequestResult)>& callbackRef,
    const std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    // context : AbilityContext
    auto contextSharedPtr = context->shared_from_this();
    asyncContext->abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(contextSharedPtr);
    if (asyncContext->abilityContext != nullptr) {
        asyncContext->uiAbilityFlag = true;
    } else {
        LOGI("convert to ability context failed");
        asyncContext->uiExtensionContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(contextSharedPtr);
        if (asyncContext->uiExtensionContext == nullptr) {
            LOGE("convert to ui extension context failed");
            return false;
        }
    }
    // permissionList
    if (cPermissionList.size == 0) {
        return false;
    }
    auto permissionList = CArrStringToVector(cPermissionList);
    asyncContext->permissionList = permissionList;
    asyncContext->callbackRef = callbackRef;
    return true;
}

void UIExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    Ace::UIContent* uiContent = nullptr;
    if (this->reqContext_->uiAbilityFlag) {
        uiContent = this->reqContext_->abilityContext->GetUIContent();
    } else {
        uiContent = this->reqContext_->uiExtensionContext->GetUIContent();
    }
    if (uiContent != nullptr) {
        LOGI("close uiextension component");
        uiContent->CloseModalUIExtension(this->sessionId_);
    }

    if (code == 0) {
        return; // code is 0 means request has return by OnResult
    }
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

UIExtensionCallback::~UIExtensionCallback()
{}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    LOGI("releaseCode is %{public}d", releaseCode);

    ReleaseOrErrorHandle(releaseCode);
}

static void GrantResultsCallbackUI(const std::vector<std::string>& permissionList,
    const std::vector<int32_t>& permissionStates, std::shared_ptr<RequestAsyncContext>& data)
{
    // only permissions which need to grant change the result, other keey as GetSelfPermissionsState result
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data->permissionsState, newGrantResults);
    RetDataCPermissionRequestResult ret{};
    fillRequestResult(ret.data, permissionList, newGrantResults, data->dialogShownResults);
    ret.code = AT_PERM_OPERA_SUCC;
    data->callbackRef(ret);
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void UIExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    LOGI("resultCode is %{public}d", resultCode);
    std::vector<std::string> permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    std::vector<int32_t> permissionStates = result.GetIntArrayParam(RESULT_KEY);

    GrantResultsCallbackUI(permissionList, permissionStates, this->reqContext_);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void UIExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI("called!");
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void UIExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI("code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseOrErrorHandle(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI("connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void UIExtensionCallback::OnDestroy()
{
    LOGI("UIExtensionAbility destructed.");
}

static Ace::ModalUIExtensionCallbacks BindCallbacks(std::shared_ptr<UIExtensionCallback> uiExtCallback)
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

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestAsyncContext> asyncContext)
{
    Ace::UIContent* uiContent = nullptr;
    int64_t beginTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (asyncContext->uiAbilityFlag) {
        while (true) {
            uiContent = asyncContext->abilityContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > MAX_WAIT_TIME)) {
                break;
            }
        }
    } else {
        while (true) {
            uiContent = asyncContext->uiExtensionContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > MAX_WAIT_TIME)) {
                break;
            }
        }
    }

    if (uiContent == nullptr) {
        LOGE("get ui content failed!");
        asyncContext->result = CjErrorCode::CJ_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT;
        return CjErrorCode::CJ_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT;
    }
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    auto uiExtensionCallbacks = BindCallbacks(uiExtCallback);
    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    if (sessionId == 0) {
        asyncContext->result = CJ_ERROR_INNER;
        return CJ_ERROR_INNER;
    }
    uiExtCallback->SetSessionId(sessionId);
    return CJ_OK;
}

static int32_t StartUIExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

void AtManagerImpl::RequestPermissionsFromUser(OHOS::AbilityRuntime::Context* context, CArrString cPermissionList,
    const std::function<void(RetDataCPermissionRequestResult)>& callbackRef)
{
    RetDataCPermissionRequestResult ret = { .code = ERR_INVALID_INSTANCE_CODE,
        .data = {
            .permissions = { .head = nullptr, .size = 0 },
            .authResults = { .head = nullptr, .size = 0 },
            .dialogShownResults = { .head = nullptr, .size = 0 } } };
    // use handle to protect asyncContext
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>();
    if (!ParseRequestPermissionFromUser(context, cPermissionList, callbackRef, asyncContext)) {
        ret.code = CjErrorCode::CJ_ERROR_PARAM_ILLEGAL;
        callbackRef(ret);
        return;
    }
    AccessTokenID tokenID = 0;
    if (asyncContext->uiAbilityFlag) {
        tokenID = asyncContext->abilityContext->GetApplicationInfo()->accessTokenId;
    } else {
        tokenID = asyncContext->uiExtensionContext->GetApplicationInfo()->accessTokenId;
    }
    if (tokenID != static_cast<AccessTokenID>(GetSelfTokenID())) {
        ret.code = CjErrorCode::CJ_ERROR_PARAM_INVALID;
        callbackRef(ret);
        return;
    }
    if (!IsDynamicRequest(asyncContext->permissionList, asyncContext->permissionsState,
        asyncContext->dialogShownResults, asyncContext->info)) {
        fillRequestResult(ret.data, asyncContext->permissionList, asyncContext->permissionsState,
            asyncContext->dialogShownResults);
        ret.code = CJ_OK;
        callbackRef(ret);
        return;
    }
    int32_t result;
    // service extension dialog
    if (asyncContext->info.grantBundleName == GRANT_ABILITY_BUNDLE_NAME) {
        LOGI("pop service extension dialog");
        result = StartServiceExtension(asyncContext);
    } else {
        LOGI("pop ui extension dialog");
        result = StartUIExtension(asyncContext);
        if (result != CJ_OK) {
            LOGI("pop uiextension dialog fail, start to pop service extension dialog");
            result = StartServiceExtension(asyncContext);
        }
    }
    ret.code = result;
    if (ret.code != CJ_OK) {
        callbackRef(ret);
        return;
    }
}

int32_t AtManagerImpl::FillPermStateChangeInfo(
    const std::string& type,
    CArrUI32 cTokenIDList,
    CArrString cPermissionList,
    int64_t callback,
    RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    PermStateChangeScope scopeInfo;
    // 1: ParseAccessTokenIDArray
    for (int64_t i = 0; i < cTokenIDList.size; i++) {
        uint32_t res = cTokenIDList.head[i];
        scopeInfo.tokenIDs.emplace_back(res);
    }
    // 2: ParseStringArray
    if (cPermissionList.size == 0) {
        LOGE("array is empty");
        return CJ_ERROR_PARAM_ILLEGAL;
    }
    for (int64_t i = 0; i < cPermissionList.size; i++) {
        std::string str = cPermissionList.head[i];
        scopeInfo.permList.emplace_back(str);
    }
    std::sort(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end());
    std::sort(scopeInfo.permList.begin(), scopeInfo.permList.end());
    registerPermStateChangeInfo.callbackRef = callback;
    registerPermStateChangeInfo.permStateChangeType = type;
    registerPermStateChangeInfo.subscriber = std::make_shared<RegisterPermStateChangeScopePtr>(scopeInfo);
    auto cFunc = reinterpret_cast<void(*)(CPermStateChangeInfo)>(callback);
    registerPermStateChangeInfo.subscriber->SetCallbackRef(CJLambda::Create(cFunc));
    registerPermStateChangeInfo.threadId = std::this_thread::get_id();
    return CJ_OK;
}

int32_t AtManagerImpl::FillUnregisterPermStateChangeInfo(
    const std::string& type,
    CArrUI32 cTokenIDList,
    CArrString cPermissionList,
    int64_t callback,
    UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo)
{
    PermStateChangeScope changeScopeInfo;
    // 1: ParseAccessTokenIDArray
    for (int i = 0; i < cTokenIDList.size; i++) {
        uint32_t res = cTokenIDList.head[i];
        changeScopeInfo.tokenIDs.emplace_back(res);
    }
    // 2: ParseStringArray
    if (cPermissionList.size == 0) {
        LOGE("array is empty");
        return CJ_ERROR_PARAM_ILLEGAL;
    }
    for (int i = 0; i < cPermissionList.size; i++) {
        std::string str = cPermissionList.head[i];
        changeScopeInfo.permList.emplace_back(str);
    }

    std::sort(changeScopeInfo.tokenIDs.begin(), changeScopeInfo.tokenIDs.end());
    std::sort(changeScopeInfo.permList.begin(), changeScopeInfo.permList.end());
    unregisterPermStateChangeInfo.callbackRef = callback;
    unregisterPermStateChangeInfo.permStateChangeType = type;
    unregisterPermStateChangeInfo.scopeInfo = changeScopeInfo;
    unregisterPermStateChangeInfo.threadId = std::this_thread::get_id();
    return CJ_OK;
}

bool AtManagerImpl::FindAndGetSubscriberInVector(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo,
    std::vector<RegisterPermStateChangeInfo*>& batchPermStateChangeRegisters)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> targetTokenIDs = unregisterPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = unregisterPermStateChangeInfo->scopeInfo.permList;
    for (const auto& item : g_permStateChangeRegisters) {
        if (unregisterPermStateChangeInfo->callbackRef != 0) {
            if (!CompareCallbackRef(item->callbackRef, unregisterPermStateChangeInfo->callbackRef, item->threadId)) {
                continue;
            }
        } else {
            // batch delete currentThread callback
            if (!IsCurrentThread(item->threadId)) {
                continue;
            }
        }
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
            LOGI("find subscriber in map");
            unregisterPermStateChangeInfo->subscriber = item->subscriber;
            batchPermStateChangeRegisters.emplace_back(item);
        }
    }
    if (!batchPermStateChangeRegisters.empty()) {
        return true;
    }
    return false;
}

void AtManagerImpl::DeleteRegisterFromVector(const PermStateChangeScope& scopeInfo, int64_t subscriberRef)
{
    std::vector<AccessTokenID> targetTokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = scopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto item = g_permStateChangeRegisters.begin();
    while (item != g_permStateChangeRegisters.end()) {
        PermStateChangeScope stateChangeScope;
        (*item)->subscriber->GetScope(stateChangeScope);
        if ((stateChangeScope.tokenIDs == targetTokenIDs) && (stateChangeScope.permList == targetPermList) &&
            CompareCallbackRef((*item)->callbackRef, subscriberRef, (*item)->threadId)) {
            LOGI("Find subscribers in vector, delete");
            delete *item;
            *item = nullptr;
            g_permStateChangeRegisters.erase(item);
            break;
        } else {
            ++item;
        }
    }
}

std::string AtManagerImpl::GetPermParamValue()
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == g_paramCache.sysCommitIdCache) {
        LOGI("sysCommitId = %{public}lld", sysCommitId);
        return g_paramCache.sysParamCache;
    }
    g_paramCache.sysCommitIdCache = sysCommitId;
    if (g_paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(PERMISSION_STATUS_CHANGE_KEY));
        if (handle == PARAM_DEFAULT_VALUE) {
            LOGE("FindParameter failed");
            return "-1";
        }
        g_paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(g_paramCache.handle));
    if (currCommitId != g_paramCache.commitIdCache) {
        char value[VALUE_MAX_LEN] = {0};
        auto ret = GetParameterValue(g_paramCache.handle, value, VALUE_MAX_LEN - 1);
        if (ret < 0) {
            LOGE("return default value, ret=%{public}d", ret);
            return "-1";
        }
        std::string resStr(value);
        g_paramCache.sysParamCache = resStr;
        g_paramCache.commitIdCache = currCommitId;
    }
    return g_paramCache.sysParamCache;
}

bool AtManagerImpl::IsExistRegister(const RegisterPermStateChangeInfo* registerPermStateChangeInfo)
{
    PermStateChangeScope targetScopeInfo;
    registerPermStateChangeInfo->subscriber->GetScope(targetScopeInfo);
    std::vector<AccessTokenID> targetTokenIDs = targetScopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = targetScopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);

    for (const auto& item : g_permStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);

        bool hasPermIntersection = false;
        // Special cases:
        // 1.Have registered full, and then register some
        // 2.Have registered some, then register full
        if (scopeInfo.permList.empty() || targetPermList.empty()) {
            hasPermIntersection = true;
        }
        for (const auto& PermItem : targetPermList) {
            if (hasPermIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.permList.begin(), scopeInfo.permList.end(), PermItem);
            if (iter != scopeInfo.permList.end()) {
                hasPermIntersection = true;
            }
        }

        bool hasTokenIdIntersection = false;

        if (scopeInfo.tokenIDs.empty() || targetTokenIDs.empty()) {
            hasTokenIdIntersection = true;
        }
        for (const auto& tokenItem : targetTokenIDs) {
            if (hasTokenIdIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end(), tokenItem);
            if (iter != scopeInfo.tokenIDs.end()) {
                hasTokenIdIntersection = true;
            }
        }

        if (hasTokenIdIntersection && hasPermIntersection &&
            CompareCallbackRef(item->callbackRef, registerPermStateChangeInfo->callbackRef, item->threadId)) {
            return true;
        }
    }
    LOGI("cannot find subscriber in vector");
    return false;
}

bool AtManagerImpl::IsDynamicRequest(const std::vector<std::string>& permissions,
    std::vector<int32_t>& permissionsState, std::vector<bool>& dialogShownResults, PermissionGrantInfo& info)
{
    std::vector<PermissionListState> permList;
    for (const auto& permission : permissions) {
        LOGI("permission: %{public}s.", permission.c_str());
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = SETTING_OPER;
        permList.emplace_back(permState);
    }
    LOGI("permList size: %{public}zu, permissions size: %{public}zu.",
        permList.size(), permissions.size());

    auto ret = AccessTokenKit::GetSelfPermissionsState(permList, info);

    for (const auto& permState : permList) {
        LOGI("permissions: %{public}s. permissionsState: %{public}u",
            permState.permissionName.c_str(), permState.state);
        permissionsState.emplace_back(permState.state);
        dialogShownResults.emplace_back(permState.state == TypePermissionOper::DYNAMIC_OPER);
    }
    if (permList.size() != permissions.size()) {
        LOGE("Returned permList size: %{public}zu.", permList.size());
        return false;
    }
    if (ret != TypePermissionOper::DYNAMIC_OPER) {
        return false;
    }
    return true;
}

// PermStateChangeContext
PermStateChangeContext::~PermStateChangeContext()
{}

// RegisterPermStateChangeScopePtr
RegisterPermStateChangeScopePtr::RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo)
    : PermStateChangeCallbackCustomize(subscribeInfo)
{}

RegisterPermStateChangeScopePtr::~RegisterPermStateChangeScopePtr()
{}

void RegisterPermStateChangeScopePtr::PermStateChangeCallback(PermStateChangeInfo& result)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        LOGE("object is invalid.");
        return;
    }
    CPermStateChangeInfo info;
    info.permStateChangeType = result.permStateChangeType;
    info.tokenID = result.tokenID;
    info.permissionName = MallocCString(result.permissionName);
    ref_(info);
}

void RegisterPermStateChangeScopePtr::SetCallbackRef(const std::function<void(CPermStateChangeInfo)>& ref)
{
    ref_ = ref;
}

void RegisterPermStateChangeScopePtr::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
}
}
} // namespace CJSystemapi
} // namespace OHOS
