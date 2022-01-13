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

#include <exception>
#include <memory>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "native_token_receptor.h"
#include "parameter.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenReceptor"};
}

// nlohmann json need the function named from_json to parse NativeTokenInfo
void from_json(const nlohmann::json& j, std::shared_ptr<NativeTokenInfoInner>& p)
{
    NativeTokenInfo native;
    if (j.find(JSON_PROCESS_NAME) != j.end()) {
        native.processName = j.at(JSON_PROCESS_NAME).get<std::string>();
        if (!DataValidator::IsProcessNameValid(native.processName)) {
            return;
        }
    } else {
        return;
    }

    if (j.find(JSON_APL) != j.end()) {
        int aplNum = j.at(JSON_APL).get<int>();
        if (DataValidator::IsAplNumValid(aplNum)) {
            native.apl = (ATokenAplEnum)aplNum;
        } else {
            return;
        }
    } else {
        return;
    }

    if (j.find(JSON_VERSION) != j.end()) {
        native.ver = j.at(JSON_VERSION).get<int>();
        if (native.ver != DEFAULT_TOKEN_VERSION) {
            return;
        }
    } else {
        return;
    }

    if (j.find(JSON_TOKEN_ID) != j.end()) {
        native.tokenID = j.at(JSON_TOKEN_ID).get<unsigned int>();
        if (native.tokenID == 0 &&
            AccessTokenIDManager::GetTokenIdTypeEnum(native.tokenID) != TOKEN_NATIVE) {
            return;
        }
    } else {
        return;
    }

    if (j.find(JSON_TOKEN_ATTR) != j.end()) {
        native.tokenAttr = j.at(JSON_TOKEN_ATTR).get<unsigned int>();
    } else {
        return;
    }

    if (j.find(JSON_DCAPS) != j.end()) {
        native.dcap = j.at(JSON_DCAPS).get<std::vector<std::string>>();
    } else {
        return;
    }
    p = std::make_shared<NativeTokenInfoInner>(native);
}

int NativeTokenReceptor::Init()
{
    std::lock_guard<std::mutex> lock(receptorThreadMutex_);
    if (ready_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: receptor thread is already running.", __func__);
        return RET_SUCCESS;
    }
    if (receptorThread_ != nullptr && receptorThread_->joinable()) {
        receptorThread_->join();
    }

    receptorThread_ = std::make_unique<std::thread>(NativeTokenReceptor::ThreadFunc, this);
    if (receptorThread_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: receptor thread is nullptr.", __func__);
        return RET_FAILED;
    }
    ready_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: init ok.", __func__);
    return RET_SUCCESS;
}

void NativeTokenReceptor::Release()
{
    std::lock_guard<std::mutex> lock(receptorThreadMutex_);
    ready_ = false;
    if (listenSocket_ >= 0) {
        close(listenSocket_);
        listenSocket_ = -1;
    }

    if (connectSocket_ >= 0) {
        close(connectSocket_);
        connectSocket_ = -1;
    }

    int ret = SetParameter(SYSTEM_PROP_NATIVE_RECEPTOR.c_str(), "false");
    if (ret != 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: set parameter failed.", __func__);
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Release ok.");
}

NativeTokenReceptor& NativeTokenReceptor::GetInstance()
{
    static NativeTokenReceptor instance;
    return instance;
}

void NativeTokenReceptor::ParserNativeRawData(const std::string& nativeRawData,
    std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos)
{
    nlohmann::json jsonRes = nlohmann::json::parse(nativeRawData, nullptr, false);
    if (jsonRes.find(JSON_KEY_NATIVE_TOKEN_INFO_JSON) != jsonRes.end()) {
        auto nativeTokenVect =
            jsonRes.at(JSON_KEY_NATIVE_TOKEN_INFO_JSON).get<std::vector<std::shared_ptr<NativeTokenInfoInner>>>();
        for (auto& token : nativeTokenVect) {
            if (token != nullptr) {
                tokenInfos.emplace_back(token);
            }
        }
    }
}

int NativeTokenReceptor::InitNativeTokenSocket()
{
    struct sockaddr_un addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (memcpy_s(addr.sun_path, sizeof(addr.sun_path), socketPath_.c_str(), sizeof(addr.sun_path) - 1) != EOK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: init socket path failed.", __func__);
        return -1;
    }

    unlink(socketPath_.c_str());
    listenSocket_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenSocket_ < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: init socket failed.", __func__);
        return -1;
    }

    socklen_t len = sizeof(struct sockaddr_un);
    int ret = bind(listenSocket_, (struct sockaddr *)(&addr), len);
    if (ret == -1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: bind socket failed.", __func__);
        close(listenSocket_);
        listenSocket_ = -1;
        return -1;
    }
    ret = listen(listenSocket_, 1);
    if (ret < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: listen socket failed.", __func__);
        remove(socketPath_.c_str());
        close(listenSocket_);
        listenSocket_ = -1;
        return -1;
    }
    return 0;
}

void NativeTokenReceptor::LoopHandler()
{
    int ret = InitNativeTokenSocket();
    if (ret < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: InitNativeTokenSocket failed.", __func__);
        return;
    }

    ret = SetParameter(SYSTEM_PROP_NATIVE_RECEPTOR.c_str(), "true");
    if (ret != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: set parameter failed.", __func__);
        return;
    }

    while (true) {
        socklen_t len = sizeof(struct sockaddr_un);
        struct sockaddr_un clientAddr;
        int connectSocket_ = accept(listenSocket_, (struct sockaddr *)(&clientAddr), &len);
        if (connectSocket_ < 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: accept fail errno %{public}d.", __func__, errno);
            continue;
        }
        std::string nativeRawData;
        char buff[MAX_RECEPTOR_SIZE + 1];
        while (true) {
            int readLen = read(connectSocket_, buff, MAX_RECEPTOR_SIZE);
            if (readLen <= 0) {
                break;
            }
            buff[readLen] = '\0';
            nativeRawData.append(buff);
        }
        close(connectSocket_);
        connectSocket_ = -1;

        std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;
        ParserNativeRawData(nativeRawData, tokenInfos);
        AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    }
}

void NativeTokenReceptor::ThreadFunc(NativeTokenReceptor *receptor)
{
    if (receptor != nullptr) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: start handler loop.", __func__);
        receptor->LoopHandler();
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: native token loop end, native token can not sync.", __func__);
        receptor->Release();
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

