/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "napi_common.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CommonNapi"};
} // namespace

bool IsCurrentThread(std::thread::id threadId)
{
    std::thread::id currentThread = std::this_thread::get_id();
    if (threadId != currentThread) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_ref can not be compared,different threadId");
        return false;
    }
    return true;
}
bool CompareCallbackRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef, std::thread::id threadId)
{
    if (!IsCurrentThread(threadId)) {
        return false;
    }
    napi_value subscriberCallback;
    NAPI_CALL_BASE(env,
        napi_get_reference_value(env, subscriberRef, &subscriberCallback), false);
    napi_value unsubscriberCallback;
    NAPI_CALL_BASE(env,
        napi_get_reference_value(env, unsubscriberRef, &unsubscriberCallback), false);
    bool result = false;
    NAPI_CALL_BASE(env,
        napi_strict_equals(env, subscriberCallback, unsubscriberCallback, &result), false);
    return result;
}

bool CheckType(const napi_env& env, const napi_value& value, const napi_valuetype& type)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != type) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch, [%{public}d]->[%{public}d]", valuetype, type);
        return false;
    }
    return true;
}

bool ParseBool(const napi_env& env, const napi_value& value, bool& result)
{
    if (!CheckType(env, value, napi_boolean)) {
        return false;
    }

    if (napi_get_value_bool(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value bool");
        return false;
    }
    return true;
}

bool ParseInt32(const napi_env& env, const napi_value& value, int32_t& result)
{
    if (!CheckType(env, value, napi_number)) {
        return false;
    }
    if (napi_get_value_int32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int32");
        return false;
    }
    return true;
}

bool ParseInt64(const napi_env& env, const napi_value& value, int64_t& result)
{
    if (!CheckType(env, value, napi_number)) {
        return false;
    }
    if (napi_get_value_int64(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int64");
        return false;
    }
    return true;
}

bool ParseUint32(const napi_env& env, const napi_value& value, uint32_t& result)
{
    if (!CheckType(env, value, napi_number)) {
        return false;
    }
    if (napi_get_value_uint32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value uint32");
        return false;
    }
    return true;
}

bool ParseString(const napi_env& env, const napi_value& value, std::string& result)
{
    if (!CheckType(env, value, napi_string)) {
        return false;
    }
    size_t size;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get string size");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), size + 1, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value string");
        return false;
    }
    return true;
}

bool ParseStringArray(const napi_env& env, const napi_value& value, std::vector<std::string>& result)
{
    if (!IsArray(env, value)) {
        return false;
    }

    uint32_t length = 0;
    napi_get_array_length(env, value, &length);

    ACCESSTOKEN_LOG_INFO(LABEL, "array size is %{public}d", length);

    if (length == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "array is empty");
        return true;
    }

    napi_value valueArray;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, value, i, &valueArray);

        std::string str;
        if (!ParseString(env, valueArray, str)) {
            return false;
        }
        result.emplace_back(str);
    }
    return true;
}

bool ParseAccessTokenIDArray(const napi_env& env, const napi_value& value, std::vector<AccessTokenID>& result)
{
    uint32_t length = 0;
    if (!IsArray(env, value)) {
        return false;
    }
    napi_get_array_length(env, value, &length);
    napi_value valueArray;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, value, i, &valueArray);
        uint32_t res;
        if (!ParseUint32(env, valueArray, res)) {
            return false;
        }
        result.emplace_back(res);
    }
    return true;
};

bool IsArray(const napi_env& env, const napi_value& value)
{
    bool isArray = false;
    napi_status ret = napi_is_array(env, value, &isArray);
    if (ret != napi_ok) {
        return false;
    }
    return isArray;
}

bool IsUndefinedOrNull(const napi_env& env, const napi_value& value)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    return (valueType == napi_undefined) || (valueType == napi_null) ;
}

bool IsNeedParseProperty(
    const napi_env& env, const napi_value& value, const std::string& key, napi_value& property)
{
    bool hasProp = false;
    property = nullptr;
    napi_has_named_property(env, value, key.c_str(), &hasProp);
    if (hasProp) {
        napi_get_named_property(env, value, key.c_str(), &property);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, property, &valueType);
        return (valueType != napi_undefined) && (valueType != napi_null);
    }
    return false;
}

bool ParseCallback(const napi_env& env, const napi_value& value, napi_ref& result)
{
    if (!CheckType(env, value, napi_function)) {
        return false;
    }
    if (napi_create_reference(env, value, 1, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value callback");
        return false;
    }
    return true;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
