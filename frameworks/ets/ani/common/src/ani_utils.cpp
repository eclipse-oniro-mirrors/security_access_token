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
#include "ani_utils.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

bool AniFindNameSpace(ani_env* env, const std::string& namespaceDescriptor, ani_namespace& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->FindNamespace(namespaceDescriptor.c_str(), &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindNamespace: %{public}u.", status);
        return false;
    }
    return true;
}

bool AniFindClass(ani_env* env, const std::string& classDescriptor, ani_class& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(classDescriptor.c_str(), &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass(%{public}s): %{public}u.",
            classDescriptor.c_str(), status);
        return false;
    }
    return true;
}

bool AniClassFindMethod(
    ani_env* env, const ani_class& aniClass, const std::string& methodDescriptor,
    const std::string& signature, ani_method& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Class_FindMethod(aniClass, methodDescriptor.c_str(), signature.c_str(), &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Class_FindMethod: %{public}u.", status);
        return false;
    }
    return true;
}

bool AniClassFindField(ani_env* env, const ani_class& aniClass, const char *fieldName, ani_field& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Class_FindField(aniClass, fieldName, &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Class_FindField failed: %{public}u.", status);
        return false;
    }
    return true;
}

bool AniParseUint32(ani_env* env, const ani_ref& aniInt, uint32_t& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_int tmp;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_CallMethodByName_Int(
        static_cast<ani_object>(aniInt), "unboxed", nullptr, &tmp)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object_CallMethodByName_Int failed: %{public}u.", status);
        return false;
    }

    out = static_cast<uint32_t>(tmp);
    return true;
}

bool AniParseAccessTokenIDArray(ani_env* env, const ani_array& array, std::vector<uint32_t>& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_size size;
    ani_status status = ANI_ERROR;
    if ((status = env->Array_GetLength(array, &size)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_GetLength: %{public}u.", status);
        return false;
    }

    for (ani_size i = 0; i < size; ++i) {
        ani_ref elementRef;
        if ((status = env->Array_Get(array, i, &elementRef)) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_Get_Ref at index %{public}zu: %{public}u.", i, status);
            return false;
        }
        uint32_t value;
        if (!AniParseUint32(env, elementRef, value)) {
            return false;
        }
        if (value == 0) {
            return false;
        }
        out.emplace_back(value);
    }
    return true;
}

std::vector<std::string> ParseAniStringVector(ani_env* env, const ani_array& aniStrArr)
{
    std::vector<std::string> out;
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return out;
    }
    ani_size size = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Array_GetLength(aniStrArr, &size)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_GetLength: %{public}u.", status);
        return out;
    }

    for (ani_size i = 0; i < size; ++i) {
        ani_ref aniRef;
        if ((status = env->Array_Get(aniStrArr, i, &aniRef)) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_Get_Ref: %{public}u.", status);
            return out;
        }

        std::string stdStr = ParseAniString(env, static_cast<ani_string>(aniRef));
        if (!stdStr.empty()) {
            out.emplace_back(stdStr);
        }
    }
    return out;
}

bool AniParseCallback(ani_env* env, const ani_ref& aniCallback, ani_ref& out)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(aniCallback, &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GlobalReference_Create: %{public}u.", status);
        return false;
    }
    return true;
}

bool AniIsRefUndefined(ani_env* env, const ani_ref& ref)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_boolean isUnd;
    ani_status status = ANI_ERROR;
    if ((status = env->Reference_IsUndefined(ref, &isUnd)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Reference_IsUndefined: %{public}u.", status);
        return false;
    }
    return isUnd ? true : false;
}

ani_string CreateAniString(ani_env* env, const std::string& str)
{
    ani_string aniStr = {};
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return aniStr;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to String_NewUTF8: %{public}u.", status);
        return aniStr;
    }
    return aniStr;
}

bool IsCurrentThread(std::thread::id threadId)
{
    return threadId == std::this_thread::get_id();
}

bool AniIsCallbackRefEqual(ani_env* env, const ani_ref& compareRef, const ani_ref& targetRref, std::thread::id threadId,
    bool& isEqual)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    if (!IsCurrentThread(threadId)) {
        return false;
    }

    ani_boolean isEq = false;
    ani_status status = ANI_ERROR;
    if ((status = env->Reference_StrictEquals(compareRef, targetRref, &isEq)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Reference_StrictEquals: %{public}u.", status);
        return false;
    }
    isEqual = isEq ? true : false;
    return true;
}

bool AniFunctionalObjectCall(ani_env *env, const ani_fn_object& fn, ani_size size, ani_ref* argv, ani_ref& result)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->FunctionalObject_Call(fn, size, argv, &result)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to AniFunctionalObjectCall: %{public}u.", status);
        return false;
    }
    return true;
}

std::string ParseAniString(ani_env* env, ani_string aniStr)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return "";
    }

    ani_size strSize;
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(aniStr, &strSize)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to String_GetUTF8Size: %{public}u.", status);
        return "";
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    if ((status = env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytesWritten)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to String_GetUTF8: %{public}u.", status);
        return "";
    }

    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

ani_ref CreateAniArrayString(ani_env* env, const std::vector<std::string>& cArray)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_size length = cArray.size();
    ani_array aArrayRef = nullptr;
    ani_ref undefinedRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetUndefined(&undefinedRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetUndefined: %{public}u.", status);
        return nullptr;
    }
    if ((status = env->Array_New(length, undefinedRef, &aArrayRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_New_Ref: %{public}u.", status);
        return nullptr;
    }
    ani_string aString = nullptr;
    for (ani_size i = 0; i < length; ++i) {
        env->String_NewUTF8(cArray[i].c_str(), cArray[i].size(), &aString);
        env->Array_Set(aArrayRef, i, aString);
    }
    ani_ref aRef = nullptr;
    if ((status = env->GlobalReference_Create(aArrayRef, &aRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GlobalReference_Create: %{public}u.", status);
        return nullptr;
    }
    return aRef;
}

ani_ref CreateAniArrayInt(ani_env* env, const std::vector<int32_t>& cArray)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_size length = cArray.size();
    ani_array aArrayInt = nullptr;
    ani_ref undefinedRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetUndefined(&undefinedRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetUndefined: %{public}u.", status);
        return nullptr;
    }
    if ((status = env->Array_New(length, undefinedRef, &aArrayInt)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_New: %{public}u.", status);
        return nullptr;
    }
    ani_class intClass {};
    ani_method intCtor {};
    if ((status = env->FindClass("std.core.Int", &intClass)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass std.core.Int: %{public}u.", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(intClass, "<ctor>", "i:", &intCtor)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Find constructor: %{public}u.", status);
        return nullptr;
    }

    for (ani_size i = 0; i < length; ++i) {
        ani_object intObj {};
        if ((status = env->Object_New(intClass, intCtor, &intObj, static_cast<ani_int>(cArray[i]))) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create Int: %{public}u.", status);
        }
        if ((status = env->Array_Set(aArrayInt, i, intObj)) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Set Array: %{public}u.", status);
        }
    }
    ani_ref aRef = nullptr;
    if ((status = env->GlobalReference_Create(aArrayInt, &aRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GlobalReference_Create: %{public}u.", status);
        return nullptr;
    }
    return aRef;
}

ani_ref CreateAniArrayBool(ani_env* env, const std::vector<bool>& cArray)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_status status = ANI_ERROR;
    ani_ref undefinedRef = nullptr;
    if ((status = env->GetUndefined(&undefinedRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetUndefined: %{public}u.", status);
        return nullptr;
    }

    ani_size length = cArray.size();
    ani_array aArrayBool = nullptr;
    if ((status = env->Array_New(length, undefinedRef, &aArrayBool)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_New_int: %{public}u.", status);
        return nullptr;
    }
    
    std::vector<ani_boolean> boolArray(length);
    for (ani_size i = 0; i < length; ++i) {
        boolArray[i] = cArray[i];
    }
    ani_class booleanClass {};
    ani_method booleanCtor {};
    if ((status = env->FindClass("std.core.Boolean", &booleanClass))!= ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass std.core.Boolean: %{public}u.", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(booleanClass, "<ctor>", "z:", &booleanCtor)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Find constructor: %{public}u.", status);
        return nullptr;
    }
    for (ani_size i = 0; i < length; ++i) {
        ani_object booleanObj {};
        if ((status = env->Object_New(booleanClass, booleanCtor, &booleanObj, boolArray[i])) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create Boolean: %{public}u.", status);
        }
        if ((status = env->Array_Set(aArrayBool, i, booleanObj)) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Set Array: %{public}u.", status);
        }
    }
    ani_ref aRef = nullptr;
    if ((status = env->GlobalReference_Create(aArrayBool, &aRef)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GlobalReference_Create: %{public}u.", status);
        return nullptr;
    }
    return aRef;
}

void DeleteReference(ani_env* env, ani_ref& ref)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        ref = nullptr;
        return;
    }

    if (ref != nullptr) {
        env->GlobalReference_Delete(ref);
        ref = nullptr;
    }
}

ani_object CreateBooleanObject(ani_env *env, bool value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_class persionCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Boolean", &persionCls)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass: %{public}u.", status);
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persionCls, "<ctor>", "z:", &personInfoCtor)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindMethod: %{public}u.", status);
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persionCls, personInfoCtor, &personInfoObj, value)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_New: %{public}u.", status);
        return nullptr;
    }
    return personInfoObj;
}

ani_object CreateIntObject(ani_env *env, int32_t value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_class persionCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Int", &persionCls)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass: %{public}u.", status);
        return nullptr;
    }
    ani_method aniMethod;
    if ((status = env->Class_FindMethod(persionCls, "<ctor>", "i:", &aniMethod)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindMethod: %{public}u.", status);
        return nullptr;
    }
    ani_object aniObject;
    if ((status = env->Object_New(persionCls, aniMethod, &aniObject, value)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_New: %{public}u.", status);
        return nullptr;
    }
    return aniObject;
}

ani_object CreateClassObject(ani_env* env, const std::string& classDescriptor)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_class aniClass;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(classDescriptor.c_str(), &aniClass)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindClass: %{public}u.", status);
        return nullptr;
    }
    ani_method aniMethod;
    if ((status = env->Class_FindMethod(aniClass, "<ctor>", ":", &aniMethod)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Class_FindMethod: %{public}u.", status);
        return nullptr;
    }
    ani_object out;
    if ((status = env->Object_New(aniClass, aniMethod, &out)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_New: %{public}u.", status);
        return nullptr;
    }
    return out;
}

ani_object CreateArrayObject(ani_env* env, uint32_t length)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return nullptr;
    }

    ani_class aniClass;
    if (!AniFindClass(env, "escompat.Array", aniClass)) {
        return nullptr;
    }
    ani_method aniMethod;
    ani_status status = ANI_ERROR;
    if ((status = env->Class_FindMethod(aniClass, "<ctor>", "i:", &aniMethod)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindMethod: %{public}u.", status);
        return nullptr;
    }
    ani_object out;
    if ((status = env->Object_New(aniClass, aniMethod, &out, length)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_New(size: %{public}d): %{public}u.", length, status);
        return nullptr;
    }
    return out;
}

bool GetBoolProperty(ani_env* env, const ani_object& object, const std::string& property, bool& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        return true;
    }

    ani_boolean boolValue;
    if ((status = env->Object_CallMethodByName_Boolean(
        static_cast<ani_object>(ref), "unboxed", nullptr, &boolValue)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get bool value of property(%{public}s): %{public}u.",
            property.c_str(), status);
        return false;
    }
    value = static_cast<bool>(boolValue);
    return true;
}

bool GetIntProperty(ani_env* env, const ani_object& object, const std::string& property, int32_t& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Property(%{public}s) is undefned!", property.c_str());
        return true;
    }

    ani_int intValue;
    if ((status = env->Object_CallMethodByName_Int(
        static_cast<ani_object>(ref), "unboxed", nullptr, &intValue)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get int value of property(%{public}s): %{public}u.",
            property.c_str(), status);
        return false;
    }
    value = static_cast<int32_t>(intValue);
    return true;
}

bool GetLongProperty(ani_env* env, const ani_object& object, const std::string& property, int64_t& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        return true;
    }

    ani_long longValue;
    if ((status = env->Object_CallMethodByName_Long(
        static_cast<ani_object>(ref), "unboxed", nullptr, &longValue)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get int64 value of property(%{public}s): %{public}u.",
            property.c_str(), status);
        return false;
    }
    value = static_cast<int64_t>(longValue);
    return true;
}

bool GetStringProperty(ani_env* env, const ani_object& object, const std::string& property, std::string& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        return true;
    }
    value = ParseAniString(env, static_cast<ani_string>(ref));
    return true;
}

bool GetEnumProperty(ani_env* env, const ani_object& object, const std::string& property, int32_t& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        return true;
    }
    ani_enum_item aniEnum = static_cast<ani_enum_item>(ref);
    ani_int aniInt;
    if ((status = env->EnumItem_GetValue_Int(aniEnum, &aniInt)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get enum value of property(%{public}s): %{public}u.",
            property.c_str(), status);
        return false;
    }
    value = static_cast<int32_t>(aniInt);
    return true;
}

bool GetStringVecProperty(
    ani_env* env, const ani_object& object, const std::string& property, std::vector<std::string>& value)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return false;
    }

    ani_ref ref;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get property(%{public}s): %{public}u.", property.c_str(), status);
        return false;
    }
    if (AniIsRefUndefined(env, ref)) {
        return true;
    }
    ani_array anirefArray = static_cast<ani_array>(ref);
    value = ParseAniStringVector(env, anirefArray);
    return true;
}

bool SetBoolProperty(ani_env* env, ani_object& object, const std::string& property, bool in)
{
    if ((env == nullptr) || (object == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is nullptr, property(%{public}s).", property.c_str());
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Boolean(
        object, property.c_str(), static_cast<ani_boolean>(in))) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set property(%{public}s) failed: %{public}u.", property.c_str(), status);
        return false;
    }
    return true;
}

bool SetIntProperty(ani_env* env, ani_object& object, const std::string& property, int32_t in)
{
    if ((env == nullptr) || (object == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is nullptr, property(%{public}s).", property.c_str());
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Int(object, property.c_str(), static_cast<ani_int>(in))) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set property(%{public}s) failed: %{public}u.", property.c_str(), status);
        return false;
    }
    return true;
}

bool SetLongProperty(ani_env* env, ani_object& aniObject, const std::string& property, int64_t in)
{
    if ((env == nullptr) || (aniObject == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is nullptr, property(%{public}s).", property.c_str());
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Long(
        aniObject, property.c_str(), static_cast<ani_long>(in))) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set property(%{public}s) failed: %{public}u.", property.c_str(), status);
        return false;
    }
    return true;
}

bool SetRefProperty(ani_env* env, ani_object& aniObject, const std::string& property, const ani_ref& in)
{
    if ((env == nullptr) || (aniObject == nullptr) || (in == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is nullptr, property(%{public}s).", property.c_str());
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(aniObject, property.c_str(), in)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set property(%{public}s) failed: %{public}u.", property.c_str(), status);
        return false;
    }
    return true;
}

bool SetOptionalIntProperty(ani_env* env, ani_object& aniObject, const std::string& property, int32_t in)
{
    if ((env == nullptr) || (aniObject == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is nullptr, property(%{public}s).", property.c_str());
        return false;
    }
    ani_object intObject = CreateIntObject(env, in);
    if (intObject == nullptr) {
        return false;
    }

    if (!SetRefProperty(env, aniObject, property.c_str(), intObject)) {
        return false;
    }

    return true;
}

bool SetStringProperty(ani_env* env, ani_object& aniObject, const std::string& property, const std::string& in)
{
    if ((env == nullptr) || (aniObject == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is null, property(%{public}s).", property.c_str());
        return false;
    }
    ani_ref aniString = static_cast<ani_ref>(CreateAniString(env, in));
    if (!SetRefProperty(env, aniObject, property.c_str(), aniString)) {
        return false;
    }
    return true;
}

bool SetEnumProperty(ani_env* env, ani_object& aniObject,
    const std::string& enumDescription, const std::string& property, uint32_t value)
{
    if ((env == nullptr) || (aniObject == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input param is null, property(%{public}s).", property.c_str());
        return false;
    }
    ani_enum aniEnum;
    ani_status status = ANI_ERROR;
    if ((status = env->FindEnum(enumDescription.c_str(), &aniEnum)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindEnum: %{public}u.", status);
        return false;
    }
    ani_enum_item aniEnumItem;
    if ((status = env->Enum_GetEnumItemByIndex(aniEnum, static_cast<ani_size>(value), &aniEnumItem)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Enum_GetEnumItemByIndex: %{public}u.", status);
        return false;
    }
    if (!SetRefProperty(env, aniObject, property.c_str(), aniEnumItem)) {
        return false;
    }
    return true;
}

ani_env* GetCurrentEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Vm is null.");
        return nullptr;
    }
    ani_env* env = nullptr;
    ani_option interopEnabled {"--interop=enable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
        if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
            return nullptr;
        }
    }
    return env;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
