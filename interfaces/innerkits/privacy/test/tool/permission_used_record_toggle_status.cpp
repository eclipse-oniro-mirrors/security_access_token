/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t SET_ARGUMENT_COUNT = 4;
constexpr int32_t GET_ARGUMENT_COUNT = 3;
constexpr int32_t SET_SUBPROFILE_ARGUMENT_COUNT = 5;
constexpr int32_t GET_SUBPROFILE_ARGUMENT_COUNT = 4;
constexpr int32_t USER_ID_ARG_INDEX = 2;
constexpr int32_t STATUS_ARG_INDEX = 3;
constexpr int32_t SET_SUBPROFILE_ARG_INDEX = 4;
constexpr int32_t GET_SUBPROFILE_ARG_INDEX = 3;
constexpr int32_t LEGACY_SUBPROFILE_ID = -1;

void PrintHelp()
{
    std::cout << "Help:\n" <<
        "  ./PermissionUsedRecordToggleStatus set <user-id> <0|1> [subprofile-id]\n" <<
        "  ./PermissionUsedRecordToggleStatus get <user-id> [subprofile-id]\n" <<
        "  0: closed, 1: open\n" << std::endl;
}

bool ParseInt32(const char* value, int32_t& result)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const long parsedValue = std::strtol(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' || parsedValue < INT32_MIN || parsedValue > INT32_MAX) {
        return false;
    }
    result = static_cast<int32_t>(parsedValue);
    return true;
}

bool ParseSetArgs(int argc, char* argv[], int32_t& userId, bool& status, int32_t& subProfileId)
{
    if (argc != SET_ARGUMENT_COUNT && argc != SET_SUBPROFILE_ARGUMENT_COUNT) {
        return false;
    }
    int32_t parsedStatus = 0;
    if (!ParseInt32(argv[USER_ID_ARG_INDEX], userId) || userId < 0 ||
        !ParseInt32(argv[STATUS_ARG_INDEX], parsedStatus)) {
        return false;
    }
    if (parsedStatus != 0 && parsedStatus != 1) {
        return false;
    }
    status = parsedStatus == 1;
    if (argc == SET_SUBPROFILE_ARGUMENT_COUNT && !ParseInt32(argv[SET_SUBPROFILE_ARG_INDEX], subProfileId)) {
        return false;
    }
    return true;
}

bool ParseGetArgs(int argc, char* argv[], int32_t& userId, int32_t& subProfileId)
{
    if (argc != GET_ARGUMENT_COUNT && argc != GET_SUBPROFILE_ARGUMENT_COUNT) {
        return false;
    }
    if (!ParseInt32(argv[USER_ID_ARG_INDEX], userId) || userId < 0) {
        return false;
    }
    if (argc == GET_SUBPROFILE_ARGUMENT_COUNT && !ParseInt32(argv[GET_SUBPROFILE_ARG_INDEX], subProfileId)) {
        return false;
    }
    return true;
}

FullTokenID CreateCallerToken(const std::string& operation)
{
    const std::vector<std::string> permissions = (operation == "set") ?
        std::vector<std::string> { "ohos.permission.PERMISSION_RECORD_TOGGLE" } :
        std::vector<std::string> { "ohos.permission.PERMISSION_USED_STATS" };
    return GetHapTokenId("PermissionUsedRecordToggleStatus", permissions);
}
} // namespace

int32_t main(int argc, char* argv[])
{
    if (argc < GET_ARGUMENT_COUNT) {
        PrintHelp();
        return 0;
    }

    const std::string operation = argv[1];
    int32_t userId = 0;
    int32_t subProfileId = LEGACY_SUBPROFILE_ID;
    bool status = true;
    const bool isSet = operation == "set";
    const bool isValid = isSet ? ParseSetArgs(argc, argv, userId, status, subProfileId) :
        (operation == "get" && ParseGetArgs(argc, argv, userId, subProfileId));
    if (!isValid) {
        PrintHelp();
        return 0;
    }

    const FullTokenID callerToken = CreateCallerToken(operation);
    SetSelfTokenID(callerToken);
    int32_t ret = RET_SUCCESS;
    if (isSet) {
        ret = PrivacyKit::SetPermissionUsedRecordToggleStatus(userId, status, subProfileId);
        std::cout << "SetPermissionUsedRecordToggleStatus, userId=" << userId <<
            ", subProfileId=" << subProfileId << ", status=" << (status ? 1 : 0) <<
            ", ret=" << ret << std::endl;
    } else {
        ret = PrivacyKit::GetPermissionUsedRecordToggleStatus(userId, status, subProfileId);
        std::cout << "GetPermissionUsedRecordToggleStatus, userId=" << userId <<
            ", subProfileId=" << subProfileId << ", status=" << (status ? 1 : 0) <<
            ", ret=" << ret << std::endl;
    }
    AccessTokenKit::DeleteToken(static_cast<AccessTokenID>(callerToken));
    return 0;
}
