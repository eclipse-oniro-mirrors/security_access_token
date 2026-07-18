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
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "os_account_manager_lite.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t OPERATION_INDEX = 1;
constexpr int32_t FIRST_VALUE_INDEX = 2;
constexpr int32_t SECOND_VALUE_INDEX = 3;
constexpr int32_t ONE_VALUE_ARG_COUNT = 3;
constexpr int32_t TWO_VALUE_ARG_COUNT = 4;
constexpr int32_t ARG_PARSE_ERROR = -1;
const std::string QUERY_BUNDLE_NAME = "QuerySubProfileInfo";
const std::string GET_LOCAL_ACCOUNT_IDENTIFIERS = "ohos.permission.GET_LOCAL_ACCOUNT_IDENTIFIERS";

void PrintHelp()
{
    std::cout << "Help:\n" <<
        "  ./QuerySubProfileInfo owner <subprofile-id>\n" <<
        "  ./QuerySubProfileInfo id <user-id> <app-index>\n" <<
        "  ./QuerySubProfileInfo index <user-id> <subprofile-id>\n" <<
        "  ./QuerySubProfileInfo foreground <user-id>\n" << std::endl;
}

bool ParseInt32(const char* value, int32_t& result)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    long parsedValue = std::strtol(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' ||
        parsedValue < std::numeric_limits<int32_t>::min() ||
        parsedValue > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    result = static_cast<int32_t>(parsedValue);
    return true;
}

FullTokenID CreateCallerToken()
{
    const std::vector<std::string> reqPerm = { GET_LOCAL_ACCOUNT_IDENTIFIERS };
    return GetHapTokenId(QUERY_BUNDLE_NAME, reqPerm);
}

int32_t QueryOwner(int argc, char* argv[])
{
    int32_t subProfileId = 0;
    if (argc != ONE_VALUE_ARG_COUNT || !ParseInt32(argv[FIRST_VALUE_INDEX], subProfileId)) {
        return ARG_PARSE_ERROR;
    }
    int32_t userId = -1;
    int32_t ret = OsAccountManagerLite::GetOsAccountLocalIdForSubProfile(subProfileId, userId);
    std::cout << "GetOsAccountLocalIdForSubProfile, subProfileId=" << subProfileId <<
        ", userId=" << userId << ", ret=" << ret << std::endl;
    return ret;
}

int32_t QuerySubProfileId(int argc, char* argv[])
{
    int32_t userId = 0;
    int32_t appIndex = 0;
    if (argc != TWO_VALUE_ARG_COUNT || !ParseInt32(argv[FIRST_VALUE_INDEX], userId) ||
        !ParseInt32(argv[SECOND_VALUE_INDEX], appIndex)) {
        return ARG_PARSE_ERROR;
    }
    int32_t subProfileId = -1;
    int32_t ret = OsAccountManagerLite::GetOsAccountSubProfileId(userId, appIndex, subProfileId);
    std::cout << "GetOsAccountSubProfileId, userId=" << userId << ", appIndex=" << appIndex <<
        ", subProfileId=" << subProfileId << ", ret=" << ret << std::endl;
    return ret;
}

int32_t QueryIndex(int argc, char* argv[])
{
    int32_t userId = 0;
    int32_t subProfileId = 0;
    if (argc != TWO_VALUE_ARG_COUNT || !ParseInt32(argv[FIRST_VALUE_INDEX], userId) ||
        !ParseInt32(argv[SECOND_VALUE_INDEX], subProfileId)) {
        return ARG_PARSE_ERROR;
    }
    int32_t appIndex = -1;
    int32_t ret = OsAccountManagerLite::GetOsAccountSubProfileIndex(userId, subProfileId, appIndex);
    std::cout << "GetOsAccountSubProfileIndex, userId=" << userId << ", subProfileId=" << subProfileId <<
        ", appIndex=" << appIndex << ", ret=" << ret << std::endl;
    return ret;
}

int32_t QueryForeground(int argc, char* argv[])
{
    int32_t userId = 0;
    if (argc != ONE_VALUE_ARG_COUNT || !ParseInt32(argv[FIRST_VALUE_INDEX], userId)) {
        return ARG_PARSE_ERROR;
    }
    int32_t subProfileId = -1;
    int32_t ret = OsAccountManagerLite::GetOsAccountForegroundSubProfileId(userId, subProfileId);
    std::cout << "GetOsAccountForegroundSubProfileId, userId=" << userId <<
        ", subProfileId=" << subProfileId << ", ret=" << ret << std::endl;
    return ret;
}

} // namespace

int32_t main(int argc, char* argv[])
{
    if (argc < ONE_VALUE_ARG_COUNT) {
        PrintHelp();
        return 0;
    }
    const FullTokenID callerToken = CreateCallerToken();
    if (callerToken == INVALID_TOKENID) {
        std::cout << "Create caller token failed." << std::endl;
        return 0;
    }
    SetSelfTokenID(callerToken);
    const std::string operation = argv[OPERATION_INDEX];
    int32_t ret = ARG_PARSE_ERROR;
    if (operation == "owner") {
        ret = QueryOwner(argc, argv);
    } else if (operation == "id") {
        ret = QuerySubProfileId(argc, argv);
    } else if (operation == "index") {
        ret = QueryIndex(argc, argv);
    } else if (operation == "foreground") {
        ret = QueryForeground(argc, argv);
    }
    AccessTokenKit::DeleteToken(static_cast<AccessTokenID>(callerToken));
    if (ret == ARG_PARSE_ERROR) {
        PrintHelp();
    }
    return 0;
}
