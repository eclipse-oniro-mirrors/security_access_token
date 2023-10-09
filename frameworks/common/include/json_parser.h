/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_FRAMEWORK_COMMON_INCLUDE_JSON_PARSER_H
#define ACCESS_TOKEN_FRAMEWORK_COMMON_INCLUDE_JSON_PARSER_H

#include <string>

#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace AccessToken {
class JsonParser final {
public:
static bool GetStringFromJson(const nlohmann::json& j, const std::string& tag, std::string& out);
static bool GetIntFromJson(const nlohmann::json& j, const std::string& tag, int& out);
static bool GetUnsignedIntFromJson(const nlohmann::json& j, const std::string& tag, unsigned int& out);
static bool GetBoolFromJson(const nlohmann::json& j, const std::string& tag, bool& out);
static int32_t ReadCfgFile(const std::string& file, std::string& rawData);
static bool IsDirExsit(const std::string& file);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif  // ACCESS_TOKEN_FRAMEWORK_COMMON_INCLUDE_JSON_PARSER_H