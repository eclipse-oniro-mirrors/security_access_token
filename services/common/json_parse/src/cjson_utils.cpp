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

#include "cjson_utils.h"
#include <cstdint>
#include <memory>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace  {
#define RECURSE_FLAG_TRUE 1
}

CJson *GetItemFromArray(const CJson* jsonArr, int32_t index)
{
    if (jsonArr == nullptr) {
        return nullptr;
    }
    return cJSON_GetArrayItem(jsonArr, index);
}

CJsonUnique CreateJsonFromString(const std::string& jsonStr)
{
    if (jsonStr.empty()) {
        return nullptr;
    }
    CJsonUnique aPtr(cJSON_Parse(jsonStr.c_str()), FreeJson);
    return aPtr;
}

CJsonUnique CreateJson(void)
{
    CJsonUnique aPtr(cJSON_CreateObject(), FreeJson);
    return aPtr;
}

CJsonUnique CreateJsonArray(void)
{
    CJsonUnique aPtr(cJSON_CreateArray(), FreeJson);
    return aPtr;
}

void FreeJson(CJson* jsonObj)
{
    cJSON_Delete(jsonObj);
    jsonObj = nullptr;
}

std::string PackJsonToString(const CJson* jsonObj)
{
    char* ptr = cJSON_PrintUnformatted(jsonObj);
    if (ptr == nullptr) {
        return std::string();
    }
    std::string ret = std::string(ptr);
    FreeJsonString(ptr);
    return ret;
}

std::string PackJsonToString(const CJsonUnique& jsonObj)
{
    return PackJsonToString(jsonObj.get());
}

void FreeJsonString(char* jsonStr)
{
    if (jsonStr != nullptr) {
        cJSON_free(jsonStr);
    }
}

CJson* GetObjFromJson(const CJson* jsonObj, const std::string& key)
{
    if (key.empty()) {
        return nullptr;
    }

    CJson* objValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objValue != nullptr && cJSON_IsObject(objValue)) {
        return objValue;
    }
    return nullptr;
}

CJson* GetObjFromJson(CJsonUnique& jsonObj, const std::string& key)
{
    return GetObjFromJson(jsonObj.get(), key);
}

CJson* GetArrayFromJson(const CJson* jsonObj, const std::string& key)
{
    if (key.empty()) {
        return nullptr;
    }

    CJson* objValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objValue != nullptr && cJSON_IsArray(objValue)) {
        return objValue;
    }
    return nullptr;
}

CJson* GetArrayFromJson(CJsonUnique& jsonObj, const std::string& key)
{
    return GetArrayFromJson(jsonObj.get(), key);
}

bool GetStringFromJson(const CJson *jsonObj, const std::string& key, std::string& out)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsString(jsonObjTmp)) {
        out = cJSON_GetStringValue(jsonObjTmp);
        return true;
    }
    return false;
}

bool GetIntFromJson(const CJson* jsonObj, const std::string& key, int32_t& value)
{
    if (key.empty()) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsNumber(jsonObjTmp)) {
        value = static_cast<int>(cJSON_GetNumberValue(jsonObjTmp));
        return true;
    }
    return false;
}

bool GetIntFromJson(const CJsonUnique& jsonObj, const std::string& key, int32_t& value)
{
    return GetIntFromJson(jsonObj.get(), key, value);
}

bool GetUnsignedIntFromJson(const CJson* jsonObj, const std::string& key, uint32_t& value)
{
    if (key.empty()) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsNumber(jsonObjTmp)) {
        value = static_cast<uint32_t>(cJSON_GetNumberValue(jsonObjTmp));
        return true;
    }
    return false;
}

bool GetUnsignedIntFromJson(const CJsonUnique& jsonObj, const std::string& key, uint32_t& value)
{
    return GetUnsignedIntFromJson(jsonObj.get(), key, value);
}

bool GetBoolFromJson(const CJson* jsonObj, const std::string& key, bool& value)
{
    if (key.empty()) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsBool(jsonObjTmp)) {
        value = cJSON_IsTrue(jsonObjTmp) ? true : false;
        return true;
    }
    return false;
}

bool GetBoolFromJson(const CJsonUnique& jsonObj, const std::string& key, bool& value)
{
    return GetBoolFromJson(jsonObj.get(), key, value);
}

bool AddObjToJson(CJson* jsonObj, const std::string& key, const CJson* childObj)
{
    if (key.empty() || childObj == nullptr) {
        return false;
    }

    CJson* tmpObj = cJSON_Duplicate(childObj, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    }
    return true;
}

bool AddObjToJson(CJsonUnique& jsonObj, const std::string& key, CJsonUnique& childObj)
{
    return AddObjToJson(jsonObj.get(), key, childObj.get());
}

bool AddObjToArray(CJson* jsonArr, CJson* item)
{
    if (item == nullptr) {
        return false;
    }

    if (!cJSON_IsArray(jsonArr)) {
        return false;
    }

    CJson* tmpObj = cJSON_Duplicate(item, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }

    bool ret = cJSON_AddItemToArray(jsonArr, tmpObj);
    return ret;
}

bool AddObjToArray(CJsonUnique& jsonArr, CJsonUnique& item)
{
    return AddObjToArray(jsonArr.get(), item.get());
}

bool AddStringToJson(CJson* jsonObj, const std::string& key, const std::string& value)
{
    if (key.empty() || value.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (cJSON_AddStringToObject(jsonObj, key.c_str(), value.c_str()) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateString(value.c_str());
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddStringToJson(CJsonUnique& jsonObj, const std::string& key, const std::string& value)
{
    return AddStringToJson(jsonObj.get(), key, value);
}

bool AddBoolToJson(CJson* jsonObj, const std::string& key, const bool value)
{
    if (key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (cJSON_AddBoolToObject(jsonObj, key.c_str(), value) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateBool(value);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddBoolToJson(CJsonUnique& jsonObj, const std::string& key, const bool value)
{
    return AddBoolToJson(jsonObj.get(), key, value);
}

bool AddIntToJson(CJson* jsonObj, const std::string& key, const int value)
{
    if (key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (cJSON_AddNumberToObject(jsonObj, key.c_str(), value) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateNumber(value);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddIntToJson(CJsonUnique& jsonObj, const std::string& key, const int value)
{
    return AddIntToJson(jsonObj.get(), key, value);
}

bool AddUnsignedIntToJson(CJson* jsonObj, const std::string& key, const uint32_t value)
{
    if (key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    double tmpValue = static_cast<double>(value);
    if (objInJson == nullptr) {
        if (cJSON_AddNumberToObject(jsonObj, key.c_str(), tmpValue) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateNumber(tmpValue);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }
    return true;
}

bool AddUnsignedIntToJson(CJsonUnique& jsonObj, const std::string& key, const uint32_t value)
{
    return AddUnsignedIntToJson(jsonObj.get(), key, value);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS