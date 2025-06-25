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
bool AniFindNameSpace(ani_env* env, const std::string& namespaceDescriptor, ani_namespace& out);
bool AniFindClass(ani_env* env, const std::string&  classDescriptor, ani_class& out);
bool AniClassFindMethod(
    ani_env* env, const ani_class& aniClass, const std::string& methodDescriptor,
    const std::string& signature, ani_method& out);
bool AniClassFindField(ani_env* env, const ani_class& aniClass, const std::string& fieldName, ani_field& out);

bool AniParseCallback(ani_env* env, const ani_ref& ani_callback, ani_ref& out);
bool AniIsRefUndefined(ani_env* env, const ani_ref& ref);

bool GetBoolProperty(ani_env* env, const ani_object& object, const std::string& property, bool& value);
bool GetIntProperty(ani_env* env, const ani_object& object, const std::string& property, int32_t& value);
bool GetLongProperty(ani_env* env, const ani_object& object, const std::string& property, int64_t& value);
bool GetStringProperty(ani_env* env, const ani_object& object, const std::string& property, std::string& value);
bool GetEnumProperty(ani_env* env, const ani_object& object, const std::string& property, int32_t& value);
bool GetStringVecProperty(
    ani_env* env, const ani_object& object, const std::string& property, std::vector<std::string>& value);

bool SetBoolProperty(ani_env* env, ani_object& object, const std::string& property, bool in);
bool SetIntProperty(ani_env* env, ani_object& object, const std::string& property, int32_t in);
bool SetLongProperty(ani_env* env, ani_object& object, const std::string& property, int64_t in);
bool SetRefProperty(ani_env* env, ani_object& object, const std::string& property, const ani_ref& in);
bool SetStringProperty(ani_env* env, ani_object& aniObject, const std::string& property, const std::string& in);
bool SetEnumProperty(
    ani_env* env, ani_object& aniObject, const std::string& enumDescription,
    const std::string& property, uint32_t value);
bool SetOptionalIntProperty(ani_env* env, ani_object& aniObject, const std::string& property, int32_t in);

bool IsCurrentThread(std::thread::id threadId);
bool AniIsCallbackRefEqual(ani_env* env, const ani_ref& compareRef, const ani_ref& targetRref, std::thread::id threadId,
    bool& isEqual);
bool AniFunctionalObjectCall(ani_env *env, const ani_fn_object& fn, ani_size size, ani_ref* argv, ani_ref& result);

// ani to naitive
std::string ParseAniString(ani_env* env, ani_string aniStr);
std::vector<std::string> ParseAniStringVector(ani_env* env, const ani_array_ref& aniStrArr);

// native to ani
ani_string CreateAniString(ani_env *env, const std::string& str);
ani_object CreateIntObject(ani_env *env, int32_t value);
ani_object CreateBooleanObject(ani_env *env, bool value);
ani_object CreateClassObject(ani_env* env, const std::string& classDescriptor);
ani_object CreateArrayObject(ani_env* env, uint32_t length);

ani_ref CreateAniArrayBool(ani_env* env, const std::vector<bool>& cArray);
ani_ref CreateAniArrayInt(ani_env* env, const std::vector<int32_t>& cArray);
ani_ref CreateAniArrayString(ani_env* env, const std::vector<std::string>& cArray);

// delete ref of GlobalReference_Create
void DeleteReference(ani_env* env, ani_ref& ref);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif /* INTERFACES_ETS_ANI_COMMON_ANI_UTILS_H */
