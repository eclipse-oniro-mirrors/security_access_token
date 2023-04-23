/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CONSTANT_H
#define CONSTANT_H

#include <map>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
class Constant {
public:
    enum OpCode {
        OP_INVALID = -1,
        OP_ANSWER_CALL = 0,
        OP_READ_CALENDAR = 1,
        OP_WRITE_CALENDAR = 2,
        OP_SEND_MESSAGES = 3,
        OP_WRITE_CALL_LOG = 4,
        OP_READ_CALL_LOG = 5,
        OP_READ_CELL_MESSAGES = 6,
        OP_MICROPHONE = 7,
        OP_RECEIVE_WAP_MESSAGES = 8,
        OP_RECEIVE_SMS = 9,
        OP_RECEIVE_MMS = 10,
        OP_READ_MESSAGES = 11,
        OP_READ_CONTACTS = 12,
        OP_WRITE_CONTACTS = 13,
        OP_LOCATION_IN_BACKGROUND = 14,
        OP_LOCATION = 15,
        OP_MEDIA_LOCATION = 16,
        OP_APPROXIMATELY_LOCATION = 17,
        OP_CAMERA = 18,
        OP_READ_MEDIA = 19,
        OP_WRITE_MEDIA = 20,
        OP_ACTIVITY_MOTION = 21,
        OP_READ_HEALTH_DATA = 22,
        OP_MANAGE_VOICEMAIL = 23,
        OP_DISTRIBUTED_DATASYNC = 24,
        OP_READ_IMAGEVIDEO = 25,
        OP_READ_AUDIO = 26,
        OP_READ_DOCUMENT = 27,
        OP_WRITE_IMAGEVIDEO = 28,
        OP_WRITE_AUDIO = 29,
        OP_WRITE_DOCUMENT = 30,
        OP_READ_WHOLE_CALENDAR = 31,
        OP_WRITE_WHOLE_CALENDAR = 32,
    };

    enum ErrorCode {
        FAILURE = -1,
        SUCCESS = 0,
    };

    const static int32_t MAX_TOTAL_RECORD = 10000;
    const static int32_t MAX_DETAIL_RECORD = 10;
    const static int64_t MILLISECONDS = 1000; // 1s = 1000ms
    const static int64_t RECORD_DELETE_TIME = 30 * 86400 * MILLISECONDS;
    const static int64_t PRECISE = 60 * MILLISECONDS;
    const static int64_t LATEST_RECORD_TIME = 7 * 86400 * MILLISECONDS;

    const static std::map<std::string, int32_t> PERMISSION_OPCODE_MAP;
public:
    static bool TransferPermissionToOpcode(const std::string& permissionName, int32_t& opCode);
    static bool TransferOpcodeToPermission(int32_t opCode, std::string& permissionName);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // CONSTANT_H
