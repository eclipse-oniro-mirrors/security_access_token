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

#include "privacy_manager.h"

#include <iostream>

#include "accesstoken_common_log.h"
#include "ani_error.h"
#include "ani_utils.h"
#include "privacy_error.h"
#include "privacy_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::mutex g_mutex;
std::vector<RegisterPermActiveChangeContext*> g_subScribers;
static constexpr size_t MAX_CALLBACK_SIZE = 200;
constexpr const char* ACTIVE_CHANGE_FIELD_CALLING_TOKEN_ID = "callingTokenId";
constexpr const char* ACTIVE_CHANGE_FIELD_TOKEN_ID = "tokenId";
constexpr const char* ACTIVE_CHANGE_FIELD_PERMISSION_NAME = "permissionName";
constexpr const char* ACTIVE_CHANGE_FIELD_DEVICE_ID = "deviceId";
constexpr const char* ACTIVE_CHANGE_FIELD_ACTIVE_STATUS = "activeStatus";
constexpr const char* ACTIVE_CHANGE_FIELD_USED_TYPE = "usedType";
}

static int32_t GetStsErrorCode(int32_t errCode)
{
    int32_t stsCode;
    switch (errCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case ERR_PERMISSION_DENIED:
            stsCode = STS_ERROR_PERMISSION_DENIED;
            break;
        case ERR_NOT_SYSTEM_APP:
            stsCode = STS_ERROR_NOT_SYSTEM_APP;
            break;
        case ERR_PARAM_INVALID:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case ERR_TOKENID_NOT_EXIST:
            stsCode = STS_ERROR_TOKENID_NOT_EXIST;
            break;
        case ERR_PERMISSION_NOT_EXIST:
            stsCode = STS_ERROR_PERMISSION_NOT_EXIST;
            break;
        case ERR_CALLBACK_ALREADY_EXIST:
        case ERR_CALLBACK_NOT_EXIST:
        case ERR_PERMISSION_ALREADY_START_USING:
        case ERR_PERMISSION_NOT_START_USING:
            stsCode = STS_ERROR_NOT_USE_TOGETHER;
            break;
        case ERR_CALLBACKS_EXCEED_LIMITATION:
            stsCode = STS_ERROR_REGISTERS_EXCEED_LIMITATION;
            break;
        case ERR_IDENTITY_CHECK_FAILED:
            stsCode = STS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERROR_IPC_REQUEST_FAIL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
            stsCode = STS_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_MALLOC_FAILED:
            stsCode = STS_ERROR_OUT_OF_MEMORY;
            break;
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "GetStsErrorCode nativeCode(%{public}d) stsCode(%{public}d).", errCode, stsCode);
    return stsCode;
}

static void AddPermissionUsedRecordExecute([[maybe_unused]] ani_env* env,
    ani_int aniTokenID, ani_string aniPermission, ani_int successCount, ani_int failCount, ani_object options)
{
    if (env == nullptr) {
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permission = ParseAniString(env, aniPermission);
    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permission))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permission.c_str());
        return;
    }

    int32_t usedType = 0;
    if (!GetEnumProperty(env, options, "usedType", usedType)) {
        return;
    }
    AddPermParamInfo info;
    info.tokenId = static_cast<AccessTokenID>(tokenID);
    info.permissionName = permission;
    info.successCount = successCount;
    info.failCount = failCount;
    info.type = static_cast<PermissionUsedType>(usedType);
    auto retCode = PrivacyKit::AddPermissionUsedRecord(info);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return;
    }
}

PermActiveStatusPtr::PermActiveStatusPtr(const std::vector<std::string>& permList)
    : PermActiveStatusCustomizedCbk(permList)
{}

PermActiveStatusPtr::~PermActiveStatusPtr()
{
    if (vm_ == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Vm is null.");
        return;
    }
    bool isSameThread = (threadId_ == std::this_thread::get_id());
    ani_env* env = isSameThread ? env_ : GetCurrentEnv(vm_);
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Current env is null.");
    } else if (ref_ != nullptr) {
        env->GlobalReference_Delete(ref_);
    }
    ref_ = nullptr;

    if (!isSameThread) {
        vm_->DetachCurrentThread();
    }
}

void PermActiveStatusPtr::SetVm(ani_vm* vm)
{
    vm_ = vm;
}

void PermActiveStatusPtr::SetEnv(ani_env* env)
{
    env_ = env;
}

void PermActiveStatusPtr::SetCallbackRef(const ani_ref& ref)
{
    ref_ = ref;
}

void PermActiveStatusPtr::SetThreadId(const std::thread::id threadId)
{
    threadId_ = threadId;
}

static ani_object ConvertActiveChangeResponse(ani_env* env, const ActiveChangeResponse& result)
{
    ani_object aniObject = CreateClassObject(env, "@ohos.privacyManager.privacyManager.ActiveChangeResponseInner");
    if (aniObject == nullptr) {
        return nullptr;
    }

    // set callingTokenID?: int  optional parameter callingTokenID need box as a object
    SetIntProperty(env, aniObject, ACTIVE_CHANGE_FIELD_CALLING_TOKEN_ID, static_cast<int32_t>(result.callingTokenID));

    // set tokenID: int
    SetIntProperty(env, aniObject, ACTIVE_CHANGE_FIELD_TOKEN_ID, static_cast<int32_t>(result.tokenID));

    // set permissionName: string
    SetStringProperty(env, aniObject, ACTIVE_CHANGE_FIELD_PERMISSION_NAME, result.permissionName);

    // set deviceId: string
    SetStringProperty(env, aniObject, ACTIVE_CHANGE_FIELD_DEVICE_ID, result.deviceId);

    // set activeStatus: PermissionActiveStatus
    const char* activeStatusDes = "@ohos.privacyManager.privacyManager.PermissionActiveStatus";
    SetEnumProperty(
        env, aniObject, activeStatusDes, ACTIVE_CHANGE_FIELD_ACTIVE_STATUS, static_cast<uint32_t>(result.type));

    // set usedType?: PermissionUsedType
    const char* permUsedTypeDes = "@ohos.privacyManager.privacyManager.PermissionUsedType";
    SetEnumProperty(
        env, aniObject, permUsedTypeDes, ACTIVE_CHANGE_FIELD_USED_TYPE, static_cast<uint32_t>(result.usedType));
    return aniObject;
}

void PermActiveStatusPtr::ActiveStatusChangeCallback(ActiveChangeResponse& activeChangeResponse)
{
    if (vm_ == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Vm is null.");
        return;
    }

    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    ani_env* env;
    if (vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "AttachCurrentThread failed!");
        return;
    }

    ani_fn_object fnObj = reinterpret_cast<ani_fn_object>(ref_);
    if (fnObj == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Reinterpret_cast failed!");
        return;
    }

    ani_object aniObject = ConvertActiveChangeResponse(env, activeChangeResponse);
    if (aniObject == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Convert object is null.");
        return;
    }
    std::vector<ani_ref> args;
    args.emplace_back(aniObject);
    ani_ref result;
    if (!AniFunctionalObjectCall(env, fnObj, args.size(), args.data(), result)) {
        return;
    }

    if (vm_->DetachCurrentThread() != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to DetachCurrentThread!");
        return;
    }
}

static bool ParseInputToRegister(const ani_string& aniType, const ani_array& aniArray,
    const ani_ref& aniCallback, RegisterPermActiveChangeContext* context, bool isReg)
{
    std::string type = ParseAniString(context->env, static_cast<ani_string>(aniType));
    std::vector<std::string> permList = ParseAniStringVector(context->env, aniArray);
    std::sort(permList.begin(), permList.end());

    bool hasCallback = true;
    if (!isReg) {
        hasCallback = !AniIsRefUndefined(context->env, aniCallback);
    }

    ani_ref callback = aniCallback; // callback: the third parameter is function
    if (hasCallback) {
        if (!AniParseCallback(context->env, aniCallback, callback)) {
            BusinessErrorAni::ThrowParameterTypeError(
                context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg("callback", "Callback"));
            return false;
        }
    }

    ani_vm* vm;
    if (context->env->GetVM(&vm) != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to GetVM!");
        return false;
    }

    context->callbackRef = callback;
    context->type = type;
    context->permissionList = permList;
    context->subscriber = std::make_shared<PermActiveStatusPtr>(permList);
    context->threadId = std::this_thread::get_id();

    context->subscriber->SetVm(vm);
    context->subscriber->SetEnv(context->env);
    context->subscriber->SetCallbackRef(callback);
    context->subscriber->SetThreadId(context->threadId);

    return true;
}

static bool IsExistRegister(const RegisterPermActiveChangeContext* context)
{
    std::vector<std::string> targetPermList;
    context->subscriber->GetPermList(targetPermList);
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& item : g_subScribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        bool hasPermIntersection = false;
        // Special cases:
        // 1.Have registered full, and then register some
        // 2.Have registered some, then register full
        if (permList.empty() || targetPermList.empty()) {
            hasPermIntersection = true;
        }
        for (const auto& PermItem : targetPermList) {
            if (hasPermIntersection) {
                break;
            }
            auto iter = std::find(permList.begin(), permList.end(), PermItem);
            if (iter != permList.end()) {
                hasPermIntersection = true;
            }
        }
        bool isEqual = true;
        if (!AniIsCallbackRefEqual(context->env, item->callbackRef, context->callbackRef, item->threadId, isEqual)) {
            return true;
        }
        if (hasPermIntersection && isEqual) {
            return true;
        }
    }
    return false;
}

static void RegisterPermActiveStatusCallback([[maybe_unused]] ani_env* env,
    ani_string aniType, ani_array aniArray, ani_ref callback)
{
    if (env == nullptr) {
        return;
    }

    RegisterPermActiveChangeContext* context = new (std::nothrow) RegisterPermActiveChangeContext();
    if (context == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to allocate memory for RegisterPermActiveChangeContext!");
        return;
    }
    context->env = env;
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {context};

    if (!ParseInputToRegister(aniType, aniArray, callback, context, true)) {
        return;
    }

    if (IsExistRegister(context)) {
        std::string errMsg = GetErrorMessage(
            STS_ERROR_NOT_USE_TOGETHER, "The API reuses the same input. The subscriber already exists.");
        BusinessErrorAni::ThrowError(
            env, STS_ERROR_NOT_USE_TOGETHER, GetErrorMessage(STS_ERROR_NOT_USE_TOGETHER, errMsg));
        return;
    }

    int32_t result = PrivacyKit::RegisterPermActiveStatusCallback(context->subscriber);
    if (result != RET_SUCCESS) {
        LOGE(PRI_DOMAIN, PRI_TAG, "RegisterPermActiveStatusCallback failed, res is %{public}d.", result);
        int32_t stsCode = GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_subScribers.size() >= MAX_CALLBACK_SIZE) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Subscribers size has reached the max %{public}zu.", MAX_CALLBACK_SIZE);
            BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_REGISTERS_EXCEED_LIMITATION,
                GetErrorMessage(STSErrorCode::STS_ERROR_REGISTERS_EXCEED_LIMITATION));
            return;
        }
        g_subScribers.emplace_back(context);
    }

    callbackPtr.release();
    LOGI(PRI_DOMAIN, PRI_TAG, "RegisterPermActiveStatusCallback success!");
    return;
}

static bool FindAndGetSubscriber(const RegisterPermActiveChangeContext* context,
    std::vector<RegisterPermActiveChangeContext*>& batchPermActiveChangeSubscribers)
{
    std::vector<std::string> targetPermList = context->permissionList;
    std::lock_guard<std::mutex> lock(g_mutex);
    bool callbackEqual;
    ani_ref callbackRef = context->callbackRef;
    bool isUndef = AniIsRefUndefined(context->env, context->callbackRef);
    for (const auto& item : g_subScribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        // targetCallback == nullptr, Unsubscribe from all callbacks under the same permList
        // targetCallback != nullptr, unregister the subscriber with same permList and callback
        if (isUndef) {
            // batch delete currentThread callback
            LOGI(PRI_DOMAIN, PRI_TAG, "Callback is null.");
            callbackEqual = IsCurrentThread(item->threadId);
        } else {
            LOGI(PRI_DOMAIN, PRI_TAG, "Compare callback.");
            if (!AniIsCallbackRefEqual(context->env, item->callbackRef, callbackRef, item->threadId, callbackEqual)) {
                continue;
            }
        }

        if (callbackEqual && (permList == targetPermList)) {
            batchPermActiveChangeSubscribers.emplace_back(item);
            if (!isUndef) {
                return true;
            }
        }
    }
    return !batchPermActiveChangeSubscribers.empty();
}

static void DeleteRegisterInVector(const RegisterPermActiveChangeContext* context)
{
    std::vector<std::string> targetPermList;
    context->subscriber->GetPermList(targetPermList);
    std::lock_guard<std::mutex> lock(g_mutex);
    auto item = g_subScribers.begin();
    while (item != g_subScribers.end()) {
        bool isEqual = true;
        if (!AniIsCallbackRefEqual(
            context->env, (*item)->callbackRef, context->callbackRef, (*item)->threadId, isEqual)) {
            continue;
        }
        if (!isEqual) {
            continue;
        }

        std::vector<std::string> permList;
        (*item)->subscriber->GetPermList(permList);
        if (permList == targetPermList) {
            delete *item;
            *item = nullptr;
            g_subScribers.erase(item);
            return;
        } else {
            ++item;
        }
    }
}

static void UnRegisterPermActiveStatusCallback([[maybe_unused]] ani_env* env,
    ani_string aniType, ani_array aniArray, ani_ref callback)
{
    if (env == nullptr) {
        return;
    }

    RegisterPermActiveChangeContext* context = new (std::nothrow) RegisterPermActiveChangeContext();
    if (context == nullptr) {
        return;
    }
    context->env = env;
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {context};
    if (!ParseInputToRegister(aniType, aniArray, callback, context, false)) {
        return;
    }

    std::vector<RegisterPermActiveChangeContext*> batchPermActiveChangeSubscribers;
    if (!FindAndGetSubscriber(context, batchPermActiveChangeSubscribers)) {
        std::string errMsg = GetErrorMessage(
            STS_ERROR_NOT_USE_TOGETHER, "The API is not used in pair with 'on'. The subscriber does not exist.");
        BusinessErrorAni::ThrowError(
            env, STS_ERROR_NOT_USE_TOGETHER, GetErrorMessage(STS_ERROR_NOT_USE_TOGETHER, errMsg));
        return;
    }

    for (const auto& item : batchPermActiveChangeSubscribers) {
        int32_t result = PrivacyKit::UnRegisterPermActiveStatusCallback(item->subscriber);
        if (result == RET_SUCCESS) {
            DeleteRegisterInVector(item);
        } else {
            LOGE(PRI_DOMAIN, PRI_TAG, "Failed to UnregisterPermActiveChangeCompleted.");
            int32_t stsCode = GetStsErrorCode(result);
            BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        }
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "UnRegisterPermActiveStatusCallback success!");
    return;
}

static void StopUsingPermissionExecute(
    [[maybe_unused]] ani_env* env, ani_int aniTokenID, ani_string aniPermission, ani_int pid)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "StopUsingPermissionExecute begin.");
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return;
    }

    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permission = ParseAniString(env, aniPermission);
    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permission))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permission.c_str());
        return;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "PermissionName : %{public}s, tokenID : %{public}u, pid : %{public}d.",
        permission.c_str(), tokenID, pid);

    auto retCode = PrivacyKit::StopUsingPermission(tokenID, permission, pid);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void StartUsingPermissionExecute([[maybe_unused]] ani_env* env,
    ani_int aniTokenID, ani_string aniPermission, ani_int pid, PermissionUsedType usedType)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "StartUsingPermissionExecute begin.");
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permission = ParseAniString(env, aniPermission);
    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permission))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permission.c_str());
        return;
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "PermissionName : %{public}s, tokenID : %{public}u, pid : %{public}d.",
        permission.c_str(), tokenID, pid);

    auto retCode = PrivacyKit::StartUsingPermission(tokenID, permission, pid, usedType);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static ani_object ConvertSingleUsedRecordDetail(ani_env* env, const UsedRecordDetail& record)
{
    ani_object arrayObj = CreateClassObject(env, "@ohos.privacyManager.privacyManager.UsedRecordDetailInner");
    if (arrayObj == nullptr) {
        return nullptr;
    }
    if (!SetIntProperty(env, arrayObj, "status", record.status)) {
        return nullptr;
    }
    if (!SetOptionalIntProperty(env, arrayObj, "lockScreenStatus", record.lockScreenStatus)) {
        return nullptr;
    }
    if (!SetLongProperty(env, arrayObj, "timestamp", record.timestamp)) {
        return nullptr;
    }
    if (!SetLongProperty(env, arrayObj, "accessDuration", record.accessDuration)) {
        return nullptr;
    }
    if (!SetOptionalIntProperty(env, arrayObj, "count", record.count)) {
        return nullptr;
    }
    if (!SetEnumProperty(env, arrayObj, "@ohos.privacyManager.privacyManager.PermissionUsedType", "usedType",
        static_cast<uint32_t>(record.type))) {
        return nullptr;
    }
    return arrayObj;
}

static ani_object ConvertUsedRecordDetails(ani_env* env, const std::vector<UsedRecordDetail>& details)
{
    ani_object arrayObj = CreateArrayObject(env, details.size());
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size index = 0;
    for (const auto& record: details) {
        ani_ref aniRecord = ConvertSingleUsedRecordDetail(env, record);
        if (aniRecord == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "aniRecord is null.");
            break;
        }
        ani_status status = env->Object_CallMethodByName_Void(
            arrayObj, "$_set", "iC{std.core.Object}:", index, aniRecord);
        if (status != ANI_OK) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Failed to Object_CallMethodByName_Void: %{public}u.", status);
            break;
        }
        ++index;
    }
    return arrayObj;
}

static ani_object ConvertSinglePermissionRecord(ani_env* env, const PermissionUsedRecord& record)
{
    ani_object arrayObj = CreateClassObject(env, "@ohos.privacyManager.privacyManager.PermissionUsedRecordInner");
    if (arrayObj == nullptr) {
        return nullptr;
    }
    if (!SetStringProperty(env, arrayObj, "permissionName", record.permissionName)) {
        return nullptr;
    }
    if (!SetIntProperty(env, arrayObj, "accessCount", record.accessCount)) {
        return nullptr;
    }
    if (!SetIntProperty(env, arrayObj, "rejectCount", record.rejectCount)) {
        return nullptr;
    }
    if (!SetLongProperty(env, arrayObj, "lastAccessTime", record.lastAccessTime)) {
        return nullptr;
    }
    if (!SetLongProperty(env, arrayObj, "lastRejectTime", record.lastRejectTime)) {
        return nullptr;
    }
    if (!SetLongProperty(env, arrayObj, "lastAccessDuration", record.lastAccessDuration)) {
        return nullptr;
    }
    if (!SetRefProperty(env, arrayObj, "accessRecords", ConvertUsedRecordDetails(env, record.accessRecords))) {
        return nullptr;
    }
    if (!SetRefProperty(env, arrayObj, "rejectRecords", ConvertUsedRecordDetails(env, record.rejectRecords))) {
        return nullptr;
    }
    return arrayObj;
}

static ani_ref ConvertPermissionRecords(ani_env* env, const std::vector<PermissionUsedRecord>& permRecords)
{
    ani_object arrayObj = CreateArrayObject(env, permRecords.size());
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size index = 0;
    for (const auto& record: permRecords) {
        ani_ref aniRecord = ConvertSinglePermissionRecord(env, record);
        if (aniRecord == nullptr) {
            break;
        }
        ani_status status = env->Object_CallMethodByName_Void(
            arrayObj, "$_set", "iC{std.core.Object}:", index, aniRecord);
        if (status != ANI_OK) {
            LOGE(PRI_DOMAIN, PRI_TAG,
                "Failed to Set permission record, status: %{public}u.", status);
            break;
        }
        ++index;
    }
    return arrayObj;
}

static ani_object ConvertBundleUsedRecord(ani_env* env, const BundleUsedRecord& record)
{
    ani_object aniRecord = CreateClassObject(env, "@ohos.privacyManager.privacyManager.BundleUsedRecordInner");
    if (aniRecord == nullptr) {
        return nullptr;
    }
    if (!SetIntProperty(env, aniRecord, "tokenId", static_cast<int32_t>(record.tokenId))) {
        return nullptr;
    }
    if (!SetBoolProperty(env, aniRecord, "isRemote", record.isRemote)) {
        return nullptr;
    }

    if (!SetStringProperty(env, aniRecord, "deviceId", record.deviceId)) {
        return nullptr;
    }

    if (!SetStringProperty(env, aniRecord, "bundleName", record.bundleName)) {
        return nullptr;
    }

    if (!SetRefProperty(env, aniRecord, "permissionRecords", ConvertPermissionRecords(env, record.permissionRecords))) {
        return nullptr;
    }
    return aniRecord;
}

static ani_object ConvertBundleUsedRecords(ani_env* env, const std::vector<BundleUsedRecord>& bundleRecord)
{
    ani_object arrayObj = CreateArrayObject(env, bundleRecord.size());
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size index = 0;
    for (const auto& record : bundleRecord) {
        ani_ref aniRecord = ConvertBundleUsedRecord(env, record);
        if (aniRecord == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "AniRecord is null.");
            continue;
        }
        ani_status status = env->Object_CallMethodByName_Void(
            arrayObj, "$_set", "iC{std.core.Object}:", index, aniRecord);
        if (status != ANI_OK) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Set bundle record fail, status: %{public}u.", status);
            continue;
        }
        ++index;
    }
    return arrayObj;
}

static ani_object ProcessRecordResult(ani_env* env, const PermissionUsedResult& result)
{
    ani_object aObject = CreateClassObject(env, "@ohos.privacyManager.privacyManager.PermissionUsedResponseInner");
    if (aObject == nullptr) {
        return nullptr;
    }
    if (!SetLongProperty(env, aObject, "beginTime", result.beginTimeMillis)) {
        return nullptr;
    }
    if (!SetLongProperty(env, aObject, "endTime", result.endTimeMillis)) {
        return nullptr;
    }

    if (!SetRefProperty(env, aObject, "bundleRecords", ConvertBundleUsedRecords(env, result.bundleRecords))) {
        return nullptr;
    }
    return aObject;
}

static bool ParseRequest(ani_env* env, const ani_object& aniRequest, PermissionUsedRequest& request)
{
    ani_class requestClass;
    if (ANI_OK != env->FindClass("@ohos.privacyManager.privacyManager.PermissionUsedRequest", &requestClass)) {
        return false;
    }
    ani_boolean isRequestObject = false;
    if (ANI_OK != env->Object_InstanceOf(static_cast<ani_object>(aniRequest), requestClass, &isRequestObject)) {
        return false;
    }
    if (!isRequestObject) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Object is not request type.");
        return false;
    }

    int32_t value;
    if (!GetIntProperty(env, aniRequest, "tokenId", value)) {
        return false;
    }
    request.tokenId = static_cast<AccessTokenID>(value);

    if (!GetBoolProperty(env, aniRequest, "isRemote", request.isRemote)) {
        return false;
    }

    if (!GetStringProperty(env, aniRequest, "deviceId", request.deviceId)) {
        return false;
    }

    if (!GetStringProperty(env, aniRequest, "bundleName", request.bundleName)) {
        return false;
    }

    if (!GetLongProperty(env, aniRequest, "beginTime", request.beginTimeMillis)) {
        return false;
    }

    if (!GetLongProperty(env, aniRequest, "endTime", request.endTimeMillis)) {
        return false;
    }

    if (!GetStringVecProperty(env, aniRequest, "permissionNames", request.permissionList)) {
        return false;
    }

    int32_t flag;
    if (!GetEnumProperty(env, aniRequest, "flag", flag)) {
        return false;
    }
    request.flag = static_cast<PermissionUsageFlag>(flag);
    return true;
}

static ani_object GetPermissionUsedRecordExecute([[maybe_unused]] ani_env* env, ani_object aniRequest)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecordExecute Call.");
    if (env == nullptr || aniRequest == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env or aniRequest is null.");
        return nullptr;
    }

    PermissionUsedRequest request;
    if (!ParseRequest(env, aniRequest, request)) {
        return nullptr;
    }

    PermissionUsedResult retResult;
    int32_t errcode = PrivacyKit::GetPermissionUsedRecords(request, retResult);
    if (errcode != ANI_OK) {
        int32_t stsCode = GetStsErrorCode(errcode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return nullptr;
    }
    return ProcessRecordResult(env, retResult);
}

static ani_object ConvertPermissionUsedTypeInfo(ani_env *env, const PermissionUsedTypeInfo& info)
{
    ani_object aObject = CreateClassObject(env, "@ohos.privacyManager.privacyManager.PermissionUsedTypeInfoInner");
    if (aObject == nullptr) {
        return nullptr;
    }
    if (!SetIntProperty(env, aObject, "tokenId", info.tokenId)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to set tokenId.");
        return nullptr;
    }
    if (!SetStringProperty(env, aObject, "permissionName", info.permissionName)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to set PermissionName.");
        return nullptr;
    }
    const char* permUsedTypeDes = "@ohos.privacyManager.privacyManager.PermissionUsedType";
    if (!SetEnumProperty(env, aObject, permUsedTypeDes, "usedType", static_cast<uint32_t>(info.type))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to set UsedType.");
        return nullptr;
    }
    return aObject;
}

static ani_ref ConvertPermissionUsedTypeInfos(ani_env* env, const std::vector<PermissionUsedTypeInfo>& infos)
{
    ani_object arrayObj = CreateArrayObject(env, infos.size());
    if (arrayObj == nullptr) {
        return nullptr;
    }
    ani_size index = 0;
    for (const auto& type : infos) {
        ani_ref aniType = ConvertPermissionUsedTypeInfo(env, type);
        if (aniType == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "AniType is null.");
            continue;
        }
        ani_status status = env->Object_CallMethodByName_Void(
            arrayObj, "$_set", "iC{std.core.Object}:", index, aniType);
        if (status != ANI_OK) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Failed to Set type, status: %{public}u.", status);
            continue;
        }
        ++index;
    }
    return arrayObj;
}

static ani_ref GetPermissionUsedTypeInfosExecute([[maybe_unused]] ani_env* env,
    ani_int aniTokenID, ani_string aniPermission)
{
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return nullptr;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permission = ParseAniString(env, static_cast<ani_string>(aniPermission));
    std::vector<PermissionUsedTypeInfo> typeInfos;
    int32_t retCode = PrivacyKit::GetPermissionUsedTypeInfos(tokenID, permission, typeInfos);
    if (retCode != RET_SUCCESS) {
        BusinessErrorAni::ThrowError(env, GetStsErrorCode(retCode),
            GetErrorMessage(GetStsErrorCode(retCode)));
        return nullptr;
    }
    return ConvertPermissionUsedTypeInfos(env, typeInfos);
}

static void SetPermissionUsedRecordToggleStatusExecute([[maybe_unused]] ani_env* env, ani_boolean status)
{
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return;
    }
    int32_t userID = 0;
    int32_t retCode = PrivacyKit::SetPermissionUsedRecordToggleStatus(userID, status);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static ani_boolean GetPermissionUsedRecordToggleStatusExecute([[maybe_unused]] ani_env* env)
{
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return false;
    }
    int32_t userID = 0;
    bool isToggleStatus = false;
    int32_t retCode = PrivacyKit::GetPermissionUsedRecordToggleStatus(userID, isToggleStatus);
    if (retCode != RET_SUCCESS) {
        BusinessErrorAni::ThrowError(env, GetStsErrorCode(retCode), GetErrorMessage(GetStsErrorCode(retCode)));
        return false;
    }
    return isToggleStatus;
}

void InitPrivacyFunction(ani_env *env)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "InitPrivacyFunction call.");
    if (env == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Env is null.");
        return;
    }
    if (env->ResetError() != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to ResetError.");
    }

    ani_namespace ns;
    if (ANI_OK != env->FindNamespace("@ohos.privacyManager.privacyManager", &ns)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to FindNamespace privacyManager.");
        return;
    }

    // namespace method input param without ani_object
    std::array nsMethods = {
        ani_native_function {"addPermissionUsedRecordExecute", nullptr,
            reinterpret_cast<void *>(AddPermissionUsedRecordExecute)},
        ani_native_function {"startUsingPermissionExecute", nullptr,
            reinterpret_cast<void *>(StartUsingPermissionExecute)},
        ani_native_function {"stopUsingPermissionExecute", nullptr,
            reinterpret_cast<void *>(StopUsingPermissionExecute)},
        ani_native_function {"getPermissionUsedRecordExecute", nullptr,
            reinterpret_cast<void *>(GetPermissionUsedRecordExecute)},
        ani_native_function {"getPermissionUsedTypeInfosExecute", nullptr,
            reinterpret_cast<void *>(GetPermissionUsedTypeInfosExecute)},
        ani_native_function {"setPermissionUsedRecordToggleStatusExecute",
            nullptr, reinterpret_cast<void *>(SetPermissionUsedRecordToggleStatusExecute)},
        ani_native_function {"getPermissionUsedRecordToggleStatusExecute",
            nullptr, reinterpret_cast<void *>(GetPermissionUsedRecordToggleStatusExecute)},
        ani_native_function {"onExecute", nullptr, reinterpret_cast<void *>(RegisterPermActiveStatusCallback)},
        ani_native_function {"offExecute", nullptr, reinterpret_cast<void *>(UnRegisterPermActiveStatusCallback)},
    };
    ani_status status = env->Namespace_BindNativeFunctions(ns, nsMethods.data(), nsMethods.size());
    if (status != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to Namespace_BindNativeFunctions status : %{public}u.", status);
    }
    if (env->ResetError() != ANI_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to ResetError.");
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "InitPrivacyFunction end.");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "ANI_Constructor begin.");
    if (vm == nullptr || result == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Vm or result is null.");
        return ANI_INVALID_ARGS;
    }
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Unsupported ANI_VERSION_1.");
        return ANI_OUT_OF_MEMORY;
    }
    InitPrivacyFunction(env);
    *result = ANI_VERSION_1;
    LOGI(PRI_DOMAIN, PRI_TAG, "ANI_Constructor end.");
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS