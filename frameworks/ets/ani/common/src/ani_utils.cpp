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

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenAniUtils" };
} // namespace

bool AniFindNameSpace(ani_env* env, const char* namespaceDescriptor, ani_namespace& out)
{
    if (env->FindNamespace(namespaceDescriptor, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindNamespace failed!");
        return false;
    }
    return true;
}

bool AniFindClass(ani_env* env, const char* classDescriptor, ani_class& out)
{
    if (env->FindClass(classDescriptor, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass failed!");
        return false;
    }
    return true;
}

bool AniClassFindMethod(ani_env* env, const ani_class& aniClass, const char* methodDescriptor, const char* signature,
    ani_method& out)
{
    if (env->Class_FindMethod(aniClass, methodDescriptor, signature, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindMethod failed!");
        return false;
    }
    return true;
}

bool AniClassFindField(ani_env* env, const ani_class& aniClass, const char *fieldName, ani_field& out)
{
    if (env->Class_FindField(aniClass, fieldName, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindField failed!");
        return false;
    }
    return true;
}

bool AniFindEnum(ani_env* env, const char *enumDescriptor, ani_enum& out)
{
    if (env->FindEnum(enumDescriptor, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindEnum failed!");
        return false;
    }
    return true;
}

bool AniGetEnumItemByIndex(ani_env* env, const ani_enum& aniEnum, ani_size index, ani_enum_item& out)
{
    if (env->Enum_GetEnumItemByIndex(aniEnum, index, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Enum_GetEnumItemByIndex failed!");
        return false;
    }
    return true;
}


bool AniParseString(ani_env* env, const ani_string& ani_str, std::string& out)
{
    ani_size strSize;
    if (env->String_GetUTF8Size(ani_str, &strSize) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8Size failed!");
        return false;
    }

    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    if (env->String_GetUTF8(ani_str, utf8Buffer, strSize + 1, &bytesWritten) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8 failed!");
        return false;
    }
    if (bytesWritten == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String is empty!");
        return false;
    }
    utf8Buffer[bytesWritten] = '\0';

    out = std::string(utf8Buffer);
    return true;
}

bool AniParseStringArray(ani_env* env, const ani_array_ref& ani_str_arr, std::vector<std::string>& out)
{
    ani_size size = 0;
    if (env->Array_GetLength(ani_str_arr, &size) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Array_GetLength failed!");
        return false;
    }

    for (ani_size i = 0; i < size; ++i) {
        ani_ref aniRef;
        if (env->Array_Get_Ref(ani_str_arr, i, &aniRef) != ANI_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Array_Get_Ref failed!");
            return false;
        }

        std::string stdStr;
        if (!AniParseString(env, static_cast<ani_string>(aniRef), stdStr)) {
            return false;
        }

        out.emplace_back(stdStr);
    }
    return true;
}

bool AniParseCallback(ani_env* env, const ani_ref& ani_callback, ani_ref& out)
{
    if (env->GlobalReference_Create(ani_callback, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GlobalReference_Create failed!");
        return false;
    }
    return true;
}

bool AniIsRefUndefined(ani_env* env, const ani_ref& ref, bool& isUndefined)
{
    ani_boolean isUnd;
    if (env->Reference_IsUndefined(ref, &isUnd) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Reference_IsUndefined failed!");
        return false;
    }
    isUndefined = isUnd ? true : false;
    return true;
}

bool AniNewString(ani_env* env, const std::string in, ani_string& out)
{
    if (env->String_NewUTF8(in.c_str(), in.size(), &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_NewUTF8 failed!");
        return false;
    }
    return true;
}

bool AniNewEnumIteam(ani_env* env, const char* enumDescriptor, ani_size index, ani_enum_item& out)
{
    ani_enum aniEnum;
    if (!AniFindEnum(env, enumDescriptor, aniEnum)) {
        return false;
    }
    return AniGetEnumItemByIndex(env, aniEnum, index, out);
}

bool AniNewClassObject(ani_env* env, const ani_class aniClass, const char* methodDescriptor, const char* signature,
    ani_object& out)
{
    ani_method aniMethod;
    if (!AniClassFindMethod(env, aniClass, methodDescriptor, signature, aniMethod)) {
        return false;
    }

    if (env->Object_New(aniClass, aniMethod, &out) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_New failed!");
        return false;
    }
    return true;
}

bool AniObjectSetFieldInt(ani_env* env, const ani_class& aniClass, ani_object& aniObject, const char* fieldName,
    ani_int in)
{
    ani_field aniField;
    if (!AniClassFindField(env, aniClass, fieldName, aniField)) {
        return false;
    }

    if (env->Object_SetField_Int(aniObject, aniField, in) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Int failed!");
        return false;
    }
    return true;
}

bool AniObjectSetFieldRef(ani_env* env, const ani_class& aniClass, ani_object& aniObject, const char* fieldName,
    const ani_ref& in)
{
    ani_field aniField;
    if (!AniClassFindField(env, aniClass, fieldName, aniField)) {
        return false;
    }

    if (env->Object_SetField_Ref(aniObject, aniField, in) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Ref failed!");
        return false;
    }
    return true;
}

bool AniObjectSetPropertyByNameInt(ani_env* env, ani_object& object, const char *propertyName, ani_int in)
{
    if (env->Object_SetPropertyByName_Int(object, propertyName, in) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetPropertyByName_Int failed!");
        return false;
    }
    return true;
}

bool AniObjectSetPropertyByNameRef(ani_env* env, ani_object& object, const char *propertyName, ani_ref in)
{
    if (env->Object_SetPropertyByName_Ref(object, propertyName, in) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetPropertyByName_Ref failed!");
        return false;
    }
    return true;
}

bool IsCurrentThread(std::thread::id threadId)
{
    std::thread::id currentThread = std::this_thread::get_id();
    if (threadId != currentThread) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Ani_ref can not be compared, different threadId.");
        return false;
    }
    return true;
}

bool AniIsCallbackRefEqual(ani_env* env, const ani_ref& compareRef, const ani_ref& targetRref, std::thread::id threadId,
    bool& isEqual)
{
    if (!IsCurrentThread(threadId)) {
        return false;
    }

    ani_boolean isEq = false;
    if (env->Reference_StrictEquals(compareRef, targetRref, &isEq) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Reference_StrictEquals failed.");
        return false;
    }
    isEqual = isEq ? true : false;
    return true;
}

bool AniFunctionalObjectCall(ani_env *env, const ani_fn_object& fn, ani_size size, ani_ref* argv, ani_ref& result)
{
    if (env->FunctionalObject_Call(fn, size, argv, &result) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AniFunctionalObjectCall failed.");
        return false;
    }
    return true;
}

void DeleteReference(ani_env* env, ani_ref& ref)
{
    if (ref != nullptr) {
        env->GlobalReference_Delete(ref);
        ref = nullptr;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
