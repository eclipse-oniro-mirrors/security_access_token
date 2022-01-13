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
#include <thread>
#include <mutex>

#include "access_token.h"
#include "nlohmann/json.hpp"
#include "native_token_info_inner.h"
#include "nocopyable.h"
#include "parameter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string JSON_KEY_NATIVE_TOKEN_INFO_JSON = "NativeTokenInfo";
const std::string SOCKET_FILE = "/data/system/token_unix_socket.socket";
constexpr int MAX_RECEPTOR_SIZE = 1024;
const std::string SYSTEM_PROP_NATIVE_RECEPTOR = "rw.nativetoken.receptor.startup";
class NativeTokenReceptor final {
public:
    static NativeTokenReceptor& GetInstance();
    virtual ~NativeTokenReceptor() = default;
    int Init();
    void Release();
    void LoopHandler();
    static void ThreadFunc(NativeTokenReceptor *receptor);

private:
    NativeTokenReceptor() : receptorThread_(nullptr), listenSocket_(-1),
        connectSocket_(-1), ready_(false), socketPath_(SOCKET_FILE) {};
    DISALLOW_COPY_AND_MOVE(NativeTokenReceptor);

    void FromJson(const nlohmann::json &jsonObject,
        std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos);
    void ParserNativeRawData(const std::string& nativeRawData,
        std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos);
    int InitNativeTokenSocket();
    void from_json(const nlohmann::json& j, NativeTokenInfo& p);

    std::unique_ptr<std::thread> receptorThread_;
    std::mutex receptorThreadMutex_;
    int listenSocket_;
    int connectSocket_;
    bool ready_;
    std::string socketPath_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_NATIVE_TOKEN_RECEPTOR_H

