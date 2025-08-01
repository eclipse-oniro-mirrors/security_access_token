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

#include "constant_common.h"
#include <string>

#include "access_token.h"
#include "parameter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* REPLACE_TARGET = "****";
constexpr const char* REPLACE_TARGET_LESS_THAN_MINLEN = "*******";
} // namespace
std::string ConstantCommon::EncryptDevId(std::string deviceId)
{
    std::string result = deviceId;
    if (deviceId.empty()) {
        return result;
    }
    if (deviceId.size() > MINDEVICEIDLEN) {
        result.replace(ENCRYPTBEGIN + ENCRYPTLEN, deviceId.size() - MINDEVICEIDLEN, REPLACE_TARGET);
    } else {
        result.replace(ENCRYPTBEGIN + 1, deviceId.size()-1, REPLACE_TARGET_LESS_THAN_MINLEN);
    }
    return result;
}

std::string ConstantCommon::GetLocalDeviceId()
{
    static std::string localDeviceId;
    if (!localDeviceId.empty()) {
        return localDeviceId;
    }
    const int32_t DEVICE_UUID_LENGTH = 65;
    char udid[DEVICE_UUID_LENGTH] = {0};
    if (GetDevUdid(udid, DEVICE_UUID_LENGTH) == 0) {
        localDeviceId = udid;
    }
    return localDeviceId;
}

bool ConstantCommon::IsPermOperatedByUser(int32_t flag)
{
    uint32_t uFlag = static_cast<uint32_t>(flag);
    return (uFlag & PERMISSION_USER_FIXED) || (uFlag & PERMISSION_USER_SET);
}

bool ConstantCommon::IsPermOperatedBySystem(int32_t flag)
{
    uint32_t uFlag = static_cast<uint32_t>(flag);
    return (uFlag & PERMISSION_SYSTEM_FIXED) || (uFlag & PERMISSION_PRE_AUTHORIZED_CANCELABLE);
}

bool ConstantCommon::IsPermGrantedBySecComp(int32_t flag)
{
    uint32_t uFlag = static_cast<uint32_t>(flag);
    return uFlag & PERMISSION_COMPONENT_SET;
}

uint32_t ConstantCommon::GetFlagWithoutSpecifiedElement(uint32_t fullFlag, uint32_t removedFlag)
{
    uint32_t unmaskedFlag = (fullFlag) & (~removedFlag);
    return unmaskedFlag;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS