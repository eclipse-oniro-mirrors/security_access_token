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
#include "to_string.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace Security {
namespace AccessToken {
const int PERMISSION_FLAG = 2;
const std::string SHORT_OPTIONS_DUMP = "ht::r::i:p:";
const std::string TOOLS_NAME = "atm";
const std::string HELP_MSG = "usage: atm <command> <option>\n"
                             "These are common atm commands list:\n"
                             "  help    list available commands\n"
                             "  dump    dumpsys command\n"
                             "  perm    grant/cancel permission\n";

const std::string HELP_MSG_DUMP =
    "usage: atm dump <option>.\n"
    "options list:\n"
    "  -h, --help                                                       list available options\n"
    "  -t, --token-info [-i <token-id>]                                 list token info in system\n"
    "  -r, --record-info [-i <token-id>] [-p <permission-name>]         list used records in system\n";

const std::string HELP_MSG_PERM =
    "usage: atm perm <option>.\n"
    "options list:\n"
    "  -h, --help                                       list available options\n"
    "  -g, --grant -i <token-id> -p <permission-name>   grant a permission by a specified token-id\n"
    "  -c, --cancel -i <token-id> -p <permission-name>  cancel a permission by a specified token-id\n";

const struct option LONG_OPTIONS_DUMP[] = {
    {"help", no_argument, nullptr, 'h'},
    {"token-info", no_argument, nullptr, 't'},
    {"record-info", no_argument, nullptr, 'r'},
    {"token-id", required_argument, nullptr, 'i'},
    {"permission-name", required_argument, nullptr, 'p'},
    {nullptr, 0, nullptr, 0}
};

const std::string SHORT_OPTIONS_PERM = "hg::c::i:p:";
const struct option LONG_OPTIONS_PERM[] = {
    {"help", no_argument, nullptr, 'h'},
    {"grant", no_argument, nullptr, 'g'},
    {"cancel", no_argument, nullptr, 'c'},
    {"token-id", required_argument, nullptr, 'i'},
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
        {"perm", std::bind(&AtmCommand::RunAsPermCommand, this)},
    };

    return ERR_OK;
}

ErrCode AtmCommand::CreateMessageMap()
{
    messageMap_ = {
    };

    return ERR_OK;
}

ErrCode AtmCommand::init()
{
    ErrCode result = ERR_OK;

    // there is no need to get proxy currently, the function used in class AccessTokenKit is static

    return result;
}

ErrCode AtmCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);

    return ERR_OK;
}

ErrCode AtmCommand::RunAsDumpCommand()
{
    ErrCode results = ERR_OK;
    OptType type = DEFAULT;
    uint32_t tokenId = 0;
    std::string permissionName = "";
    int counter = 0;
    while (true) {
        counter++;
        int32_t option = getopt_long(argc_, argv_, SHORT_OPTIONS_DUMP.c_str(), LONG_OPTIONS_DUMP, nullptr);
        if (optind < 0 || optind > argc_) {
            return ERR_INVALID_VALUE;
        }

        if (option == -1) {
            if (counter == 1) {
                results = RunAsCommandError();
            }
            break;
        }

        if (option == '?') {
            results = RunAsCommandMissingOptionArgument();
            break;
        }

        results = RunAsCommandExistentOptionArgument(option, type, tokenId, permissionName);
    }

    if (results != ERR_OK) {
        resultReceiver_.append(HELP_MSG_DUMP + "\n");
    } else {
        results = RunCommandByOperationType(type, tokenId, permissionName);
    }
    return results;
}

ErrCode AtmCommand::RunAsPermCommand()
{
    ErrCode result = ERR_OK;
    OptType type = DEFAULT;
    uint32_t tokenId = 0;
    std::string permissionName = "";
    int counter = 0;
    while (true) {
        counter++;
        int32_t option = getopt_long(argc_, argv_, SHORT_OPTIONS_PERM.c_str(), LONG_OPTIONS_PERM, nullptr);
        if (optind < 0 || optind > argc_) {
            return ERR_INVALID_VALUE;
        }

        if (option == -1) {
            if (counter == 1) {
                result = RunAsCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsCommandMissingOptionArgument();
            break;
        }

        result = RunAsCommandExistentOptionArgument(option, type, tokenId, permissionName);
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_PERM + "\n");
    } else {
        result = RunCommandByOperationType(type, tokenId, permissionName);
    }
    return result;
}

ErrCode AtmCommand::RunCommandByOperationType(const OptType& type,
    uint32_t& tokenId, std::string& permissionName)
{
    std::string dumpInfo = "";
    ErrCode ret = ERR_OK;
    switch (type) {
        case DUMP_TOKEN:
            AccessTokenKit::DumpTokenInfo(tokenId, dumpInfo);
            break;
        case DUMP_RECORD:
            dumpInfo = DumpRecordInfo(tokenId, permissionName);
            break;
        case PERM_GRANT:
        case PERM_REVOKE:
            ret = ModifyPermission(type, tokenId, permissionName);
            if (ret == ERR_OK) {
                dumpInfo = "Success";
            } else {
                dumpInfo = "Failure";
            }
            break;
        default:
            resultReceiver_.append("error: miss option \n");
            return ERR_INVALID_VALUE;
    }
    resultReceiver_.append(dumpInfo + "\n");
    return ret;
}

ErrCode AtmCommand::ModifyPermission(const OptType& type, uint32_t& tokenId, std::string& permissionName)
{
    if (tokenId == 0 || permissionName.empty()) {
        return ERR_INVALID_VALUE;
    }

    int result = 0;
    if (type == PERM_GRANT) {
        result = AccessTokenKit::GrantPermission(tokenId, permissionName, PERMISSION_FLAG);
    } else if (type == PERM_REVOKE) {
        result = AccessTokenKit::RevokePermission(tokenId, permissionName, PERMISSION_FLAG);
    } else {
        return ERR_INVALID_VALUE;
    }
    if (result != 0) {
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

ErrCode AtmCommand::RunAsCommandError(void)
{
    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'atm dump' with no option: atm dump
        // 'atm dump' with a wrong argument: atm dump xxx

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }
    return result;
}

ErrCode AtmCommand::RunAsCommandMissingOptionArgument(void)
{
    ErrCode result = ERR_OK;
    switch (optopt) {
        case 'h':
            // 'atm dump -h'
            result = ERR_INVALID_VALUE;
            break;
        case 'i':
        case 'p':
        case 'g':
        case 'c':
            resultReceiver_.append("error: option ");
            resultReceiver_.append("requires a value.\n");
            result = ERR_INVALID_VALUE;
            break;
        default: {
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }
    return result;
}

ErrCode AtmCommand::RunAsCommandExistentOptionArgument(
    const int& option, OptType& type, uint32_t& tokenId, std::string& permissionName)
{
    ErrCode result = ERR_OK;
    switch (option) {
        case 'h':
            // 'atm dump -h'
            result = ERR_INVALID_VALUE;
            break;
        case 't':
            type = DUMP_TOKEN;
            break;
        case 'r':
            type = DUMP_RECORD;
            break;
        case 'g':
            type = PERM_GRANT;
            break;
        case 'c':
            type = PERM_REVOKE;
            break;
        case 'i':
            if (optarg != nullptr) {
                tokenId = static_cast<uint32_t>(std::atoi(optarg));
            }
            break;
        case 'p':
            if (optarg != nullptr) {
                permissionName = optarg;
            }
            break;
        default:
            break;
    }
    return result;
}

std::string AtmCommand::DumpRecordInfo(uint32_t tokenId, const std::string& permissionName)
{
    PermissionUsedRequest request;
    request.tokenId = tokenId;
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    if (!permissionName.empty()) {
        request.permissionList.emplace_back(permissionName);
    }

    PermissionUsedResult result;
    if (PrivacyKit::GetPermissionUsedRecords(request, result) != 0) {
        return "";
    }

    std::string dumpInfo;
    ToString::PermissionUsedResultToString(result, dumpInfo);
    return dumpInfo;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
