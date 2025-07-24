/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <cstdint>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "cJSON.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef cJSON CJson;
typedef std::unique_ptr<CJson, std::function<void(CJson *ptr)>> CJsonUnique;

/* NO Need to call FreeJson to free the returned pointer when it's no longer in use. */
CJsonUnique CreateJsonFromString(const std::string& jsonStr);
/* NO Need to call FreeJson to free the returned pointer when it's no longer in use. */
CJsonUnique CreateJson(void);
/* NO Need to call FreeJson to free the returned pointer when it's no longer in use. */
CJsonUnique CreateJsonArray(void);
void FreeJson(CJson* jsonObj);

/* NO Need to call FreeJsonString to free the returned pointer when it's no longer in use. */
std::string PackJsonToString(const CJson* jsonObj);
std::string PackJsonToString(const CJsonUnique& jsonObj);
void FreeJsonString(char* jsonStr);

/*
 * Can't release the returned pointer, otherwise, an exception may occur.
 * It refers to the parent object(param--jsonObj)'s memory.
 * It will be recycled along with jsonObj when jsonObj is released.
 */
CJson* GetObjFromJson(const CJson* jsonObj, const std::string& key);
CJson* GetObjFromJson(CJsonUnique& jsonObj, const std::string& key);
CJson* GetArrayFromJson(const CJson* jsonObj, const std::string& key);
CJson* GetArrayFromJson(CJsonUnique& jsonObj, const std::string& key);
bool GetArrayFromJson(const CJson* jsonObj, const std::string& key, std::vector<std::string>& out);

/*
* Return a copy of string in jsonObj in std::string
*/
bool GetStringFromJson(const CJson *jsonObj, const std::string& key, std::string& out);

bool GetIntFromJson(const CJson* jsonObj, const std::string& key, int32_t& value);
bool GetIntFromJson(const CJsonUnique& jsonObj, const std::string& key, int32_t& value);
bool GetUnsignedIntFromJson(const CJson* jsonObj, const std::string& key, uint32_t& value);
bool GetUnsignedIntFromJson(const CJsonUnique& jsonObj, const std::string& key, uint32_t& value);
bool GetBoolFromJson(const CJson* jsonObj, const std::string& key, bool& value);
bool GetBoolFromJson(const CJsonUnique& jsonObj, const std::string& key, bool& value);

bool AddObjToJson(CJson* jsonObj, const std::string& key, const CJson* childObj);
bool AddObjToJson(CJsonUnique& jsonObj, const std::string& key, CJsonUnique& childObj);
bool AddObjToArray(CJson* jsonArr, CJson* item);
bool AddObjToArray(CJsonUnique& jsonArr, CJsonUnique& item);
bool AddStringToJson(CJson* jsonObj, const std::string& key, const std::string& value);
bool AddStringToJson(CJsonUnique& jsonObj, const std::string& key, const std::string& value);
bool AddBoolToJson(CJson* jsonObj, const std::string& key, const bool value);
bool AddBoolToJson(CJsonUnique& jsonObj, const std::string& key, const bool value);
bool AddIntToJson(CJson* jsonObj, const std::string& key, const int value);
bool AddIntToJson(CJsonUnique& jsonObj, const std::string& key, const int value);
bool AddUnsignedIntToJson(CJson* jsonObj, const std::string& key, const uint32_t value);
bool AddUnsignedIntToJson(CJsonUnique& jsonObj, const std::string& key, const uint32_t value);
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif
 