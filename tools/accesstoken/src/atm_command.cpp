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

#include "atm_command.h"
#include <getopt.h>
#include <string>
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "singleton.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string SHORT_OPTIONS_DUMP = "htr::b:p:";
const struct option LONG_OPTIONS_DUMP[] = {
    {"help", no_argument, nullptr, 'h'},
    {"token-info", no_argument, nullptr, 't'},
    {"record-info", no_argument, nullptr, 'r'},
    {"bundle-name", required_argument, nullptr, 'b'},
    {"permission-name", required_argument, nullptr, 'p'},
    {nullptr, 0, nullptr, 0}
};

AtmCommand::AtmCommand(int argc, char *argv[]) : ShellCommand(argc, argv, TOOLS_NAME)
{}

ErrCode AtmCommand::CreateCommandMap()
{
    commandMap_ = {
        {"help", std::bind(&AtmCommand::RunAsHelpCommand, this)},
        {"dump", std::bind(&AtmCommand::RunAsDumpCommand, this)},
    };

    return OHOS::ERR_OK;
}

ErrCode AtmCommand::CreateMessageMap()
{
    messageMap_ = {
    };

    return OHOS::ERR_OK;
}

ErrCode AtmCommand::init()
{
    ErrCode result = OHOS::ERR_OK;

    // there is no need to get proxy currently, the function used in class AccessTokenKit is static

    return result;
}

ErrCode AtmCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);

    return OHOS::ERR_OK;
}

ErrCode AtmCommand::RunAsDumpCommand()
{
    ErrCode result = OHOS::ERR_OK;
    std::string dumpInfo = "";
    bool isDumpTokenInfo = false;
    bool isDumpRecordInfo = false;
    std::string bundleName = "";
    std::string permissionName = "";
    int option = -1;
    int counter = 0;
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_DUMP.c_str(), LONG_OPTIONS_DUMP, nullptr);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }

        if (option == -1) {
            if (counter == 1) {
                if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
                    result = OHOS::ERR_INVALID_VALUE;
                }
            }
            break;
        }

        if (option == '?') {
            result = RunAsDumpCommandMissingOptionArgument();
            break;
        }

        result = RunAsDumpCommandExistentOptionArgument(
            option, isDumpTokenInfo, isDumpRecordInfo, bundleName, permissionName);

    }

    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_DUMP + "\n");
    } else {
        if (isDumpTokenInfo) {
            AccessTokenKit::DumpTokenInfo(dumpInfo);
            resultReceiver_.append(dumpInfo + "\n");
        }
        if (isDumpRecordInfo) {
            dumpInfo = PrivacyKit::DumpRecordInfo(bundleName, permissionName);
            resultReceiver_.append(dumpInfo + "\n");
        }
    }
    return result;
}

ErrCode AtmCommand::RunAsDumpCommandMissingOptionArgument(void)
{
    ErrCode result = ERR_OK;
    switch (optopt) {
        case 'h' : {
            // 'atm dump -h'
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        case 'b' : {
            // 'atm dump -b' with no argument
            resultReceiver_.append("error: option ");
            resultReceiver_.append("requires a value.\n");
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        case 'p' : {
            // 'atm dump -p' with no argument
            resultReceiver_.append("error: option ");
            resultReceiver_.append("requires a value.\n");
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
        default: {
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            resultReceiver_.append(unknownOptionMsg);
            result = OHOS::ERR_INVALID_VALUE;
            break;
        }
    }
    return result;
}

ErrCode AtmCommand::RunAsDumpCommandExistentOptionArgument(const int &option,
    bool &isDumpTokenInfo, bool &isDumpRecordInfo, std::string& bundleName, std::string& permissionName)
{
    ErrCode result = ERR_OK;
    switch (option) {
        case 'h':
            // 'atm dump -h'
            result = OHOS::ERR_INVALID_VALUE;
            break;
        case 't':
            isDumpTokenInfo = true;
            break;
        case 'r':
            isDumpRecordInfo = true;
            break;
        case 'b':
            isDumpRecordInfo = true;
            if (optarg != nullptr) {
                bundleName = optarg;;
            }
            break;
        case 'p':
            isDumpRecordInfo = true;
            if (optarg != nullptr) {
                permissionName = optarg;
            }
            break;
        default:
            break;
    }
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
