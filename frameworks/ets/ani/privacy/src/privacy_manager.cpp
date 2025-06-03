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

#include "accesstoken_log.h"
#include "ani_error.h"
#include "ani_utils.h"
#include "privacy_error.h"
#include "privacy_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AniPrivacyManager" };
std::mutex g_mutex;
std::vector<RegisterPermActiveChangeContext*> g_subScribers;
static constexpr size_t MAX_CALLBACK_SIZE = 200;
static constexpr ani_size ACTIVE_CHANGE_TYPE_INDEX_ONE = 1;
static constexpr ani_size ACTIVE_CHANGE_TYPE_INDEX_TWO = 2;
static constexpr ani_size PERMMISSION_USED_TYPE_INDEX_ONE = 1;
static constexpr ani_size PERMMISSION_USED_TYPE_INDEX_TWO = 2;
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
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetStsErrorCode nativeCode(%{public}d) stsCode(%{public}d).", errCode, stsCode);
    return stsCode;
}

static void AddPermissionUsedRecordSync(ani_env* env, const AddPermParamInfo& info)
{
    auto retCode = PrivacyKit::AddPermissionUsedRecord(info);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "call addPermissionUsedRecord retCode : %{public}d", retCode);
}

static void AddPermissionUsedRecord([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string permissionName, ani_int successCount, ani_int failCount, ani_object options)
{
    if (env == nullptr) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }
    ani_size strSize;
    ani_status status = ANI_ERROR;
    if (ANI_OK != (status = env->String_GetUTF8Size(permissionName, &strSize))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8Size_Faild status : %{public}d", status);
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    if (ANI_OK != (status = env->String_GetUTF8(permissionName, utf8Buffer, strSize + 1, &bytesWritten))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get String_GetUTF8 Faild status : %{public}d", status);
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }
    utf8Buffer[bytesWritten] = '\0';
    std::string outputPermissionName = std::string(utf8Buffer);
    ani_ref usedTypeRef;
    if (ANI_OK != (status = env->Object_GetPropertyByName_Ref(options, "usedType", &usedTypeRef))) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_GetFieldByName_Ref Faild status : %{public}d", status);
        return;
    }
    ani_int usedType = 0;
    ani_boolean isUndefined = true;
    if (ANI_OK != (status = env->Reference_IsUndefined(usedTypeRef, &isUndefined))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "status : %{public}d", status);
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }
    if (!isUndefined) {
        ani_enum_item usedTypeEnum = static_cast<ani_enum_item>(usedTypeRef);
        if (ANI_OK != env->EnumItem_GetValue_Int(usedTypeEnum, &usedType)) {
            BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
            return;
        }
    }
    AddPermParamInfo info;
    info.tokenId = static_cast<AccessTokenID>(tokenID);
    info.permissionName = outputPermissionName;
    info.successCount = successCount;
    info.failCount = failCount;
    info.type = static_cast<PermissionUsedType>(usedType);
    AddPermissionUsedRecordSync(env, info);
}

PermActiveStatusPtr::PermActiveStatusPtr(const std::vector<std::string>& permList)
    : PermActiveStatusCustomizedCbk(permList)
{}

PermActiveStatusPtr::~PermActiveStatusPtr()
{
    if (vm_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "vm is nullptr;");
        return;
    }

    bool isSameThread = (threadId_ == std::this_thread::get_id());
    ani_env* env;
    if (isSameThread) {
        env = env_;
    } else {
        ani_option interopEnabled {"--interop=disable", nullptr};
        ani_options aniArgs {1, &interopEnabled};
        vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    }

    if (ref_ != nullptr) {
        env->GlobalReference_Delete(ref_);
        ref_ = nullptr;
    }

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

static bool GenerateAniClassAndObject(ani_env* env, ani_class& aniClass, ani_object& aniObject)
{
    const char* classDescriptor = "L@ohos/privacyManager/privacyManager/ActiveChangeResponseInner;";
    if (!AniFindClass(env, classDescriptor, aniClass)) {
        return false;
    }

    const char* methodDescriptor = "<ctor>";
    const char* signature = nullptr;
    if (!AniNewClassObject(env, aniClass, methodDescriptor, signature, aniObject)) {
        return false;
    }

    return true;
}

static bool SetOptionalIntProperty(ani_env* env, ani_object& aniObject, const char* propertyName, const ani_int in)
{
    ani_class aniClass;
    const char* classDescriptor = "Lstd/core/Int;";
    if (!AniFindClass(env, classDescriptor, aniClass)) {
        return false;
    }

    const char* methodDescriptor = "<ctor>"; // <ctor> means constructor
    const char* signature = "I:V"; // I:V means input is int, return is void
    ani_method aniMethod;
    if (!AniClassFindMethod(env, aniClass, methodDescriptor, signature, aniMethod)) {
        return false;
    }

    ani_object intObject;
    if (env->Object_New(aniClass, aniMethod, &intObject, in) != ANI_OK) {
        return false;
    }

    if (!AniObjectSetPropertyByNameRef(env, aniObject, propertyName, intObject)) {
        return false;
    }

    return true;
}

static bool SetStringProperty(ani_env* env, ani_object& aniObject, const char* propertyName, const std::string in)
{
    ani_string aniString;
    if (!AniNewString(env, in, aniString)) {
        return false;
    }

    if (!AniObjectSetPropertyByNameRef(env, aniObject, propertyName, aniString)) {
        return false;
    }

    return true;
}

static bool SetEnumProperty(ani_env* env, ani_object& aniObject, const char* enumDescription, const char* propertyName,
    ani_size index)
{
    ani_enum_item aniEnumItem;
    if (!AniNewEnumIteam(env, enumDescription, index, aniEnumItem)) {
        return false;
    }

    if (!AniObjectSetPropertyByNameRef(env, aniObject, propertyName, aniEnumItem)) {
        return false;
    }

    return true;
}

static bool TransFormActiveChangeTypeToIndex(ActiveChangeType type, ani_size& index)
{
    if (type == ActiveChangeType::PERM_INACTIVE) {
        index = 0;
    } else if (type == ActiveChangeType::PERM_ACTIVE_IN_FOREGROUND) {
        index = ACTIVE_CHANGE_TYPE_INDEX_ONE;
    } else if (type == ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND) {
        index = ACTIVE_CHANGE_TYPE_INDEX_TWO;
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid ActiveChangeType value!");
        return false;
    }
    return true;
}

static bool TransFormPermissionUsedTypeToIndex(PermissionUsedType type, ani_size& index)
{
    if (type == PermissionUsedType::NORMAL_TYPE) {
        index = 0;
    } else if (type == PermissionUsedType::PICKER_TYPE) {
        index = PERMMISSION_USED_TYPE_INDEX_ONE;
    } else if (type == PermissionUsedType::SECURITY_COMPONENT_TYPE) {
        index = PERMMISSION_USED_TYPE_INDEX_TWO;
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid PermissionUsedType value!");
        return false;
    }
    return true;
}

static void ConvertActiveChangeResponse(ani_env* env, const ActiveChangeResponse& result, ani_object& aniObject)
{
    // class implements from interface should use property, independent class use field
    ani_class aniClass;
    if (!GenerateAniClassAndObject(env, aniClass, aniObject)) {
        return;
    }

    // set callingTokenID?: int  optional parameter callingTokenID need box as a object
    if (!SetOptionalIntProperty(env, aniObject, ACTIVE_CHANGE_FIELD_CALLING_TOKEN_ID,
        static_cast<ani_int>(result.callingTokenID))) {
        return;
    }

    // set tokenID: int
    if (!AniObjectSetPropertyByNameInt(env, aniObject, ACTIVE_CHANGE_FIELD_TOKEN_ID,
        static_cast<ani_int>(result.tokenID))) {
        return;
    }

    // set permissionName: string
    if (!SetStringProperty(env, aniObject, ACTIVE_CHANGE_FIELD_PERMISSION_NAME, result.permissionName)) {
        return;
    }

    // set deviceId: string
    if (!SetStringProperty(env, aniObject, ACTIVE_CHANGE_FIELD_DEVICE_ID, result.deviceId)) {
        return;
    }

    // set activeStatus: PermissionActiveStatus
    ani_size index = 0;
    if (!TransFormActiveChangeTypeToIndex(result.type, index)) {
        return;
    }
    const char* activeStatusDes = "L@ohos/privacyManager/privacyManager/PermissionActiveStatus;";
    if (!SetEnumProperty(env, aniObject, activeStatusDes, ACTIVE_CHANGE_FIELD_ACTIVE_STATUS, index)) {
        return;
    }

    // set usedType?: PermissionUsedType
    index = 0;
    if (!TransFormPermissionUsedTypeToIndex(result.usedType, index)) {
        return;
    }
    const char* permUsedTypeDes = "L@ohos/privacyManager/privacyManager/PermissionUsedType;";
    if (!SetEnumProperty(env, aniObject, permUsedTypeDes, ACTIVE_CHANGE_FIELD_USED_TYPE, index)) {
        return;
    }
}

void PermActiveStatusPtr::ActiveStatusChangeCallback(ActiveChangeResponse& activeChangeResponse)
{
    if (vm_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "vm is nullptr;");
        return;
    }

    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    ani_env* env;
    if (vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AttachCurrentThread failed!");
        return;
    }

    ani_fn_object fnObj = reinterpret_cast<ani_fn_object>(ref_);
    if (fnObj == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Reinterpret_cast failed!");
        return;
    }

    ani_object aniObject;
    ConvertActiveChangeResponse(env, activeChangeResponse, aniObject);

    std::vector<ani_ref> args;
    args.emplace_back(aniObject);
    ani_ref result;
    if (!AniFunctionalObjectCall(env, fnObj, args.size(), args.data(), result)) {
        return;
    }

    if (vm_->DetachCurrentThread() != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "DetachCurrentThread failed!");
        return;
    }
}

static bool ParseInputToRegister(const ani_string& aniType, const ani_array_ref& aniArray,
    const ani_ref& aniCallback, RegisterPermActiveChangeContext* context, bool isReg)
{
    std::string type; // type: the first parameter is string
    if (!AniParseString(context->env, aniType, type)) {
        BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg("type", "string"));
        return false;
    }

    std::vector<std::string> permList; // permissionList: the second parameter is Array<string>
    if (!AniParseStringArray(context->env, aniArray, permList)) {
        BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg(
            "permissionList", "Array<Permissions>"));
        return false;
    }
    std::sort(permList.begin(), permList.end());

    bool hasCallback = true;
    if (!isReg) {
        bool isUndefined = true;
        if (!AniIsRefUndefined(context->env, aniCallback, isUndefined)) {
            BusinessErrorAni::ThrowError(
                context->env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID));
            return false;
        }
        hasCallback = !isUndefined;
    }

    ani_ref callback = nullptr; // callback: the third parameter is function
    if (hasCallback) {
        if (!AniParseCallback(context->env, aniCallback, callback)) {
            BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg(
                "callback", "Callback"));
            return false;
        }
    }

    ani_vm* vm;
    if (context->env->GetVM(&vm) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetVM failed!");
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
    ani_string aniType, ani_array_ref aniArray, ani_ref callback)
{
    if (env == nullptr) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }

    RegisterPermActiveChangeContext* context = new (std::nothrow) RegisterPermActiveChangeContext();
    if (context == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to allocate memory for RegisterPermActiveChangeContext!");
        BusinessErrorAni::ThrowError(env, STS_ERROR_OUT_OF_MEMORY, GetErrorMessage(
            STSErrorCode::STS_ERROR_OUT_OF_MEMORY));
        return;
    }
    context->env = env;
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {context};

    if (!ParseInputToRegister(aniType, aniArray, callback, context, true)) {
        return;
    }

    if (IsExistRegister(context)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "Subscribe failed. The current subscriber has existed or Reference_StrictEquals failed!");
        BusinessErrorAni::ThrowError(
            env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER, GetErrorMessage(STSErrorCode::STS_ERROR_NOT_USE_TOGETHER));
        return;
    }

    int32_t result = PrivacyKit::RegisterPermActiveStatusCallback(context->subscriber);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterPermActiveStatusCallback failed, res is %{public}d", result);
        int32_t stsCode = GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_subScribers.size() >= MAX_CALLBACK_SIZE) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Subscribers size has reached the max %{public}zu.", MAX_CALLBACK_SIZE);
            BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_REGISTERS_EXCEED_LIMITATION,
                GetErrorMessage(STSErrorCode::STS_ERROR_REGISTERS_EXCEED_LIMITATION));
            return;
        }
        g_subScribers.emplace_back(context);
    }

    callbackPtr.release();
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterPermActiveStatusCallback success!");
    return;
}

static bool IsRefUndefined(ani_env* env, const ani_ref& ref)
{
    bool isUndef = false;
    if (!AniIsRefUndefined(env, ref, isUndef)) {
        return false;
    }
    return isUndef;
}

static bool FindAndGetSubscriber(const RegisterPermActiveChangeContext* context,
    std::vector<RegisterPermActiveChangeContext*>& batchPermActiveChangeSubscribers)
{
    std::vector<std::string> targetPermList = context->permissionList;
    std::lock_guard<std::mutex> lock(g_mutex);
    bool callbackEqual;
    ani_ref callbackRef = context->callbackRef;
    bool isUndef = IsRefUndefined(context->env, context->callbackRef);
    for (const auto& item : g_subScribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        // targetCallback == nullptr, Unsubscribe from all callbacks under the same permList
        // targetCallback != nullptr, unregister the subscriber with same permList and callback
        if (isUndef) {
            // batch delete currentThread callback
            ACCESSTOKEN_LOG_INFO(LABEL, "Callback is nullptr.");
            callbackEqual = IsCurrentThread(item->threadId);
        } else {
            ACCESSTOKEN_LOG_INFO(LABEL, "Compare callback.");
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
    if (!batchPermActiveChangeSubscribers.empty()) {
        return true;
    }
    return false;
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
    ani_string aniType, ani_array_ref aniArray, ani_ref callback)
{
    if (env == nullptr) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }

    RegisterPermActiveChangeContext* context = new (std::nothrow) RegisterPermActiveChangeContext();
    if (context == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to allocate memory for RegisterPermActiveChangeContext!");
        BusinessErrorAni::ThrowError(env, STS_ERROR_OUT_OF_MEMORY, GetErrorMessage(
            STSErrorCode::STS_ERROR_OUT_OF_MEMORY));
        return;
    }
    context->env = env;
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {context};

    if (!ParseInputToRegister(aniType, aniArray, callback, context, false)) {
        return;
    }

    std::vector<RegisterPermActiveChangeContext*> batchPermActiveChangeSubscribers;
    if (!FindAndGetSubscriber(context, batchPermActiveChangeSubscribers)) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "Unsubscribe failed. The current subscriber does not exist or Reference_StrictEquals failed!");
        BusinessErrorAni::ThrowError(
            env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER, GetErrorMessage(STSErrorCode::STS_ERROR_NOT_USE_TOGETHER));
        return;
    }

    for (const auto& item : batchPermActiveChangeSubscribers) {
        int32_t result = PrivacyKit::UnRegisterPermActiveStatusCallback(item->subscriber);
        if (result != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterPermActiveChangeCompleted failed");
            int32_t stsCode = GetStsErrorCode(result);
            BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
            return;
        }

        DeleteRegisterInVector(item);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "UnRegisterPermActiveStatusCallback success!");
    return;
}

static void StopUsingPermissionExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string permissionName, ani_int pid)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "StopUsingPermissionExecute begin.");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env null");
        return;
    }

    std::string permissionNameString;
    if (!AniParseString(env, permissionName, permissionNameString)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL,
        "PermissionName : %{public}s, tokenID : %{public}u, pid : %{public}d",
        permissionNameString.c_str(), tokenID, pid);

    auto retCode = PrivacyKit::StopUsingPermission(tokenID, permissionNameString, pid);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void StartUsingPermissionExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string permissionName, ani_int pid, PermissionUsedType usedType)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "StartUsingPermissionExecute begin.");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env null");
        return;
    }

    std::string permissionNameString;
    if (!AniParseString(env, permissionName, permissionNameString)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL,
        "PermissionName : %{public}s, tokenID : %{public}u, pid : %{public}d, UsedType : %{public}d",
        permissionNameString.c_str(), tokenID, pid, usedType);

    auto retCode = PrivacyKit::StartUsingPermission(tokenID, permissionNameString, pid, usedType);
    if (retCode != RET_SUCCESS) {
        int32_t stsCode = GetStsErrorCode(retCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}
extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    if (vm == nullptr || result == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_MEMORY;
    }

    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return ANI_NOT_FOUND;
    }

    const char* className = "L@ohos/privacyManager/privacyManager/PrivacyManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "addPermissionUsedRecordSync",
            "ILstd/core/String;IIL@ohos/privacyManager/privacyManager/AddPermissionUsedRecordOptionsInner;:V",
            reinterpret_cast<void*>(AddPermissionUsedRecord) },
        ani_native_function { "stopUsingPermissionExecute",
            nullptr,
            reinterpret_cast<void*>(StopUsingPermissionExecute) },
        ani_native_function { "startUsingPermissionExecute",
            nullptr,
            reinterpret_cast<void*>(StartUsingPermissionExecute) },
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", className);
        return ANI_ERROR;
    };

    static const char *name = "L@ohos/privacyManager/privacyManager;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(name, &ns)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindNamespace %{public}s failed.", name);
        return ANI_ERROR;
    }

    // namespace method input param without ani_object
    std::array nsMethods = {
        ani_native_function { "on", nullptr, reinterpret_cast<void *>(RegisterPermActiveStatusCallback) },
        ani_native_function { "off", nullptr, reinterpret_cast<void *>(UnRegisterPermActiveStatusCallback) },
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, nsMethods.data(), nsMethods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Namespace_BindNativeFunctions %{public}s failed.", name);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS