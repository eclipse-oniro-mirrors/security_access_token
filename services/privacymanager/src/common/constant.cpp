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

#include "constant.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::map<std::string, int32_t> Constant::PERMISSION_OPCODE_MAP = {
    std::map<std::string, int32_t>::value_type("ohos.permission.ANSWER_CALL", Constant::OP_ANSWER_CALL),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CALENDAR", Constant::OP_READ_CALENDAR),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CALENDAR", Constant::OP_WRITE_CALENDAR),
    std::map<std::string, int32_t>::value_type("ohos.permission.SEND_MESSAGES", Constant::OP_SEND_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CALL_LOG", Constant::OP_WRITE_CALL_LOG),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CALL_LOG", Constant::OP_READ_CALL_LOG),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CELL_MESSAGES", Constant::OP_READ_CELL_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.MICROPHONE", Constant::OP_MICROPHONE),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.RECEIVE_WAP_MESSAGES", Constant::OP_RECEIVE_WAP_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.RECEIVE_SMS", Constant::OP_RECEIVE_SMS),
    std::map<std::string, int32_t>::value_type("ohos.permission.RECEIVE_MMS", Constant::OP_RECEIVE_MMS),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_MESSAGES", Constant::OP_READ_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CONTACTS", Constant::OP_READ_CONTACTS),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CONTACTS", Constant::OP_WRITE_CONTACTS),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.LOCATION_IN_BACKGROUND", Constant::OP_LOCATION_IN_BACKGROUND),
    std::map<std::string, int32_t>::value_type("ohos.permission.LOCATION", Constant::OP_LOCATION),
    std::map<std::string, int32_t>::value_type("ohos.permission.MEDIA_LOCATION", Constant::OP_MEDIA_LOCATION),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.APPROXIMATELY_LOCATION", Constant::OP_APPROXIMATELY_LOCATION),
    std::map<std::string, int32_t>::value_type("ohos.permission.CAMERA", Constant::OP_CAMERA),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_MEDIA", Constant::OP_READ_MEDIA),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_MEDIA", Constant::OP_WRITE_MEDIA),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACTIVITY_MOTION", Constant::OP_ACTIVITY_MOTION),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_HEALTH_DATA", Constant::OP_READ_HEALTH_DATA),
    std::map<std::string, int32_t>::value_type("ohos.permission.MANAGE_VOICEMAIL", Constant::OP_MANAGE_VOICEMAIL),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.DISTRIBUTED_DATASYNC", Constant::OP_DISTRIBUTED_DATASYNC),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_IMAGEVIDEO", Constant::OP_READ_IMAGEVIDEO),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_AUDIO", Constant::OP_READ_AUDIO),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_DOCUMENT", Constant::OP_READ_DOCUMENT),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_IMAGEVIDEO", Constant::OP_WRITE_IMAGEVIDEO),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_AUDIO", Constant::OP_WRITE_AUDIO),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_DOCUMENT", Constant::OP_WRITE_DOCUMENT),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WHOLE_CALENDAR", Constant::OP_READ_WHOLE_CALENDAR),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.WRITE_WHOLE_CALENDAR", Constant::OP_WRITE_WHOLE_CALENDAR),
};

bool Constant::TransferPermissionToOpcode(const std::string& permissionName, int32_t& opCode)
{
    if (PERMISSION_OPCODE_MAP.count(permissionName) == 0) {
        return false;
    }
    opCode = PERMISSION_OPCODE_MAP.at(permissionName);
    return true;
}

bool Constant::TransferOpcodeToPermission(int32_t opCode, std::string& permissionName)
{
    auto iter = std::find_if(PERMISSION_OPCODE_MAP.begin(), PERMISSION_OPCODE_MAP.end(),
        [opCode](const std::map<std::string, int32_t>::value_type item) {
            return item.second == opCode;
        });
    if (iter == PERMISSION_OPCODE_MAP.end()) {
        return false;
    }
    permissionName = iter->first;
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS