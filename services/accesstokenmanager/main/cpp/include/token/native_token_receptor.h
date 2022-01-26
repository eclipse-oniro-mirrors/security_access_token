/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_NATIVE_TOKEN_RECEPTOR_H
#define ACCESSTOKEN_NATIVE_TOKEN_RECEPTOR_H

#include <memory>
#include <string>

#include "access_token.h"
#include "nlohmann/json.hpp"
#include "native_token_info_inner.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string NATIVE_TOKEN_CONFIG_FILE = "/data/service/el0/access_token/nativetoken.json";
constexpr int MAX_NATIVE_CONFIG_FILE_SIZE = 5 * 1024 * 1024; // 5M
constexpr size_t BUFFER_SIZE = 1024;
class NativeTokenReceptor final {
public:
    static NativeTokenReceptor& GetInstance();
    virtual ~NativeTokenReceptor() = default;
    int Init();

private:
    NativeTokenReceptor() : ready_(false) {};
    DISALLOW_COPY_AND_MOVE(NativeTokenReceptor);
    int ReadCfgFile(std::string &nativeRawData);
    void FromJson(const nlohmann::json &jsonObject,
        std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos);
    void ParserNativeRawData(const std::string& nativeRawData,
        std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos);
    void from_json(const nlohmann::json& j, NativeTokenInfo& p);

    bool ready_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_NATIVE_TOKEN_RECEPTOR_H
