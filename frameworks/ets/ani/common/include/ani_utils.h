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

#ifndef INTERFACES_ETS_ANI_COMMON_ANI_UTILS_H
#define INTERFACES_ETS_ANI_COMMON_ANI_UTILS_H

#include <thread>
#include <string>
#include <vector>

#include "ani.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool AniFindNameSpace(ani_env* env, const char* namespaceDescriptor, ani_namespace& out);
bool AniFindClass(ani_env* env, const char* classDescriptor, ani_class& out);
bool AniClassFindMethod(ani_env* env, const ani_class& aniClass, const char* methodDescriptor, const char* signature,
    ani_method& out);
bool AniClassFindField(ani_env* env, const ani_class& aniClass, const char *fieldName, ani_field& out);
bool AniFindEnum(ani_env* env, const char *enumDescriptor, ani_enum& out);
bool AniGetEnumItemByIndex(ani_env* env, const ani_enum& aniEnum, ani_size index, ani_enum_item& out);

bool AniParseString(ani_env* env, const ani_string& ani_str, std::string& out);
bool AniParseStringArray(ani_env* env, const ani_array_ref& ani_str_arr, std::vector<std::string>& out);
bool AniParseCallback(ani_env* env, const ani_ref& ani_callback, ani_ref& out);
bool AniIsRefUndefined(ani_env* env, const ani_ref& ref);

bool AniNewString(ani_env* env, const std::string in, ani_string& out);
bool AniNewEnumIteam(ani_env* env, const char* enumDescriptor, ani_size index, ani_enum_item& out);
bool AniNewClassObject(ani_env* env, const ani_class aniClass, const char* methodDescriptor, const char* signature,
    ani_object& out);

bool AniObjectSetFieldInt(ani_env* env, const ani_class& aniClass, ani_object& aniObject, const char* fieldName,
    ani_int in);
bool AniObjectSetFieldRef(ani_env* env, const ani_class& aniClass, ani_object& aniObject, const char* fieldName,
    const ani_ref& in);
bool AniObjectSetPropertyByNameInt(ani_env* env, ani_object& object, const char *propertyName, int32_t in);
bool AniObjectSetPropertyByNameRef(ani_env* env, ani_object& object, const char *propertyName, ani_ref in);

bool IsCurrentThread(std::thread::id threadId);
bool AniIsCallbackRefEqual(ani_env* env, const ani_ref& compareRef, const ani_ref& targetRref, std::thread::id threadId,
    bool& isEqual);
bool AniFunctionalObjectCall(ani_env *env, const ani_fn_object& fn, ani_size size, ani_ref* argv, ani_ref& result);
std::string ANIStringToStdString(ani_env* env, ani_string aniStr);
bool AniParaseArrayString([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_array_ref arrayObj, std::vector<std::string>& permissionList);
ani_ref ConvertAniArrayBool(ani_env* env, const std::vector<bool>& cArray);
ani_ref ConvertAniArrayInt(ani_env* env, const std::vector<int32_t>& cArray);
ani_ref ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray);

ani_object CreateBoolean(ani_env *env, ani_boolean value);} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ETS_ANI_COMMON_ANI_UTILS_H */
