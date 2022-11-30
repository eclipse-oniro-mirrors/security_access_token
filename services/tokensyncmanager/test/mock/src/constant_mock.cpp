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
#include "constant.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string REPLACE_TARGET = "****";
} // namespace
const std::string Constant::COMMAND_RESULT_SUCCESS = "success";
const std::string Constant::COMMAND_RESULT_FAILED = "execute command failed";

const int32_t Constant::SUCCESS;
const int32_t Constant::FAILURE;
const int32_t Constant::FAILURE_BUT_CAN_RETRY;
const int32_t Constant::INVALID_COMMAND;
const int32_t Constant::STATUS_CODE_BEFORE_RPC;

std::string ConstantCommon::EncryptDevId(std::string deviceId)
{
    std::string result = deviceId;
    if (deviceId.size() > MINDEVICEIDLEN) {
        result.replace(ENCRYPTBEGIN + ENCRYPTLEN, deviceId.size() - MINDEVICEIDLEN, REPLACE_TARGET);
    } else {
        result.replace(ENCRYPTBEGIN, deviceId.size(), REPLACE_TARGET);
    }
    return result;
}

std::string ConstantCommon::GetLocalDeviceId()
{
    return "local:udid-001";
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
