/*
 * Copyright (c) 2024-22025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_FUZZDATA_TEMPLATE_H
#define ACCESSTOKEN_FUZZDATA_TEMPLATE_H

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"
#include "accesstoken_kit.h"
#include "permission_map.h"
#include "securec.h"

static OHOS::Security::AccessToken::AccessTokenID TransfterStrToAccesstokenID(const std::string& numStr)
{
    size_t index = 0;
    while (index < numStr.length()) {
        if (!std::isdigit(numStr[index])) {
            break;
        }
        ++index;
    }
    if (index != numStr.length()) {
        return 0;
    }
    OHOS::Security::AccessToken::AccessTokenID id =
        static_cast<OHOS::Security::AccessToken::AccessTokenID>(std::stoi(numStr));
    return id;
}

static void GetTokenIdList(std::vector<OHOS::Security::AccessToken::AccessTokenID> &tokenIdList)
{
    std::string dumpInfo;
    OHOS::Security::AccessToken::AtmToolsParamInfo info;
    OHOS::Security::AccessToken::AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    std::istringstream iss(dumpInfo);
    std::string line;
    while (std::getline(iss, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string numStr = line.substr(0, pos);
            OHOS::Security::AccessToken::AccessTokenID id = TransfterStrToAccesstokenID(numStr);
            if (id != OHOS::Security::AccessToken::INVALID_TOKENID) {
                tokenIdList.push_back(id);
            }
        }
    }
}

static void GetProcessList(std::vector<std::string> &processList)
{
    std::string dumpInfo;
    OHOS::Security::AccessToken::AtmToolsParamInfo info;
    OHOS::Security::AccessToken::AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    std::istringstream stream(dumpInfo);
    std::string line;
    while (std::getline(stream, line)) {
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string process = line.substr(pos + 1);
            process.erase(0, process.find_first_not_of(" \t"));
            processList.emplace_back(process);
        }
    }
}

OHOS::Security::AccessToken::AccessTokenID ConsumeTokenId(FuzzedDataProvider &provider)
{
    static std::vector<OHOS::Security::AccessToken::AccessTokenID> tokenIdList;
    static bool isIntialize = false;
    if (!isIntialize) {
        GetTokenIdList(tokenIdList);
        isIntialize = true;
    }
    OHOS::Security::AccessToken::AccessTokenID tokenId = 0;
    if (provider.ConsumeBool() || tokenIdList.empty()) {
        tokenId = provider.ConsumeIntegral<OHOS::Security::AccessToken::AccessTokenID>();
    } else {
        tokenId = tokenIdList[
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(tokenIdList.size() - 1))];
    }

    return tokenId;
}

std::string ConsumePermissionName(FuzzedDataProvider &provider)
{
    std::string permissionName;
    if (provider.ConsumeBool()) {
        permissionName = provider.ConsumeRandomLengthString();
    } else {
        permissionName = OHOS::Security::AccessToken::TransferOpcodeToPermission(
            provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(OHOS::Security::AccessToken::GetDefPermissionsSize()) - 1), permissionName);
    }
    return permissionName;
}

std::string ConsumeProcessName(FuzzedDataProvider &provider)
{
    static std::vector<std::string> processList;
    static bool isIntialize = false;
    if (!isIntialize) {
        GetProcessList(processList);
        isIntialize = true;
    }
    std::string process;
    if (provider.ConsumeBool() || processList.empty()) {
        process = provider.ConsumeRandomLengthString();
    } else {
        process = processList[
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(processList.size() - 1))];
    }

    return process;
}

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr uint32_t BOOL_MODULO_NUM = 2;
}
class AccessTokenFuzzData {
public:
    explicit AccessTokenFuzzData(const uint8_t *data, const size_t size)
        : data_(data), size_(size), pos_(0) {}

    template <class T> T GetData()
    {
        T object{};
        size_t objectSize = sizeof(object);
        if (data_ == nullptr || objectSize > size_ - pos_) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, data_ + pos_, objectSize);
        if (ret != EOK) {
            return {};
        }
        pos_ += objectSize;
        return object;
    }

    std::string GenerateStochasticString()
    {
        uint8_t strlen = GetData<uint8_t>();

        char cstr[strlen + 1];
        cstr[strlen] = '\0';

        for (uint8_t i = 0; i < strlen; i++) {
            char tmp = GetData<char>();
            if (tmp == '\0') {
                tmp = '1';
            }
            cstr[i] = tmp;
        }
        std::string str(cstr);
        return str;
    }

    template <class T> T GenerateStochasticEnmu(T enmuMax)
    {
        T enmuData = static_cast<T>(GetData<uint32_t>() % (static_cast<uint32_t>(enmuMax) + 1));
        return enmuData;
    }

    bool GenerateStochasticBool()
    {
        return (GetData<uint32_t>() % BOOL_MODULO_NUM) == 0;
    }

private:
    const uint8_t *data_;
    const size_t size_;
    size_t pos_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_FUZZDATA_TEMPLATE_H
