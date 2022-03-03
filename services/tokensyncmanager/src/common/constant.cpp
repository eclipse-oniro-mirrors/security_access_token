/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "constant.h"
#include "parameter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string Constant::COMMAND_RESULT_SUCCESS = "success";
const std::string Constant::COMMAND_RESULT_FAILED = "execute command failed";

std::string Constant::EncryptDevId(std::string deviceId)
{
    std::string result = deviceId;
    if (deviceId.size() >= ENCRYPTLEN) {
        result.replace(ENCRYPTBEGIN, ENCRYPTEND, "****");
    } else {
        result.replace(ENCRYPTBEGIN, result.size() - 1, "****");
    }
    return result;
}

std::string Constant::GetLocalDeviceId()
{
    char deviceIdCharArray[Constant::DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(deviceIdCharArray, Constant::DEVICE_UUID_LENGTH);
    return deviceIdCharArray;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
