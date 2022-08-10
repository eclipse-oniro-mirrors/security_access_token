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

static bool inline Check(const napi_env env, const napi_value value,const napi_valuetype type)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != type) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return false;
    }
    return true;
}

bool ParseBool(const napi_env env, const napi_value value)
{
    if (!Check(env, value, napi_boolean)) {
        return 0;
    }
    bool result = 0;
    if (napi_get_value_bool(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value bool");
        return 0;
    }
    return result;
}

int32_t ParseInt32(const napi_env env, const napi_value value)
{
    if (!Check(env, value, napi_number)) {
        return 0;
    }
    int32_t result = 0;
    if (napi_get_value_int32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int32");
        return 0;
    }
    return result;
}

int64_t ParseInt64(const napi_env env, const napi_value value)
{
    if (!Check(env, value, napi_number)) {
        return 0;
    }
    int64_t result = 0;
    if (napi_get_value_int64(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int64");
        return 0;
    }
    return result;
}

uint32_t ParseUint32(const napi_env env, const napi_value value)
{
    if (!Check(env, value, napi_number)) {
        return 0;
    }
    uint32_t result = 0;
    if (napi_get_value_uint32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value uint32");
        return 0;
    }
    return result;
}

std::string ParseString(const napi_env env, const napi_value value)
{
    if (!Check(env, value, napi_string)) {
        return "";
    }
    size_t size;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get string size");
        return "";
    }
    std::string str;
    str.reserve(size + 1);
    str.resize(size);
    if (napi_get_value_string_utf8(env, value, str.data(), size + 1, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get string value");
        return "";
    }
    return str;
}

std::vector<std::string> ParseStringArray(const napi_env env, const napi_value value)
{
    std::vector<std::string> res;
    uint32_t length = 0;
    napi_valuetype valuetype = napi_undefined;

    napi_get_array_length(env, value, &length);
    napi_value valueArray;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, value, i, &valueArray);

        napi_typeof(env, valueArray, &valuetype);
        if (valuetype == napi_string) {
            res.emplace_back(ParseString(env, valueArray));
        }
    }
    return res;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS