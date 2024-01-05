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

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "to_string.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t MIN_ARGUMENT_NUMBER = 2;
static constexpr int32_t MAX_ARGUMENT_NUMBER = 4096;
static const std::string HELP_MSG_NO_OPTION = "error: you must specify an option at least.\n";
static const std::string SHORT_OPTIONS_DUMP = "ht::r::i:p:b:n:";
static const std::string TOOLS_NAME = "atm";
static const std::string HELP_MSG =
    "usage: atm <command> <option>\n"
    "These are common atm commands list:\n"
    "  help    list available commands\n"
    "  dump    dumpsys command\n"
    "  perm    grant/cancel permission\n";

static const std::string HELP_MSG_DUMP =
    "usage: atm dump <option>.\n"
    "options list:\n"
    "  -h, --help                                               list available options\n"
    "  -t, --token-info                                         list all token info in system\n"
    "  -t, --token-info -i <token-id>                           list single token info by specific tokenId\n"
    "  -t, --token-info -b <bundle-name>                        list all token info by specific bundleName\n"
    "  -t, --token-info -n <process-name>                       list single token info by specific native processName\n"
    "  -r, --record-info [-i <token-id>] [-p <permission-name>] list used records in system\n";

static const std::string HELP_MSG_PERM =
    "usage: atm perm <option>.\n"
    "options list:\n"
    "  -h, --help                                       list available options\n"
    "  -g, --grant -i <token-id> -p <permission-name>   grant a permission by a specified token-id\n"
    "  -c, --cancel -i <token-id> -p <permission-name>  cancel a permission by a specified token-id\n";

static const struct option LONG_OPTIONS_DUMP[] = {
    {"help", no_argument, nullptr, 'h'},
    {"token-info", no_argument, nullptr, 't'},
    {"record-info", no_argument, nullptr, 'r'},
    {"token-id", required_argument, nullptr, 'i'},
    {"permission-name", required_argument, nullptr, 'p'},
    {"bundle-name", required_argument, nullptr, 'b'},
    {"process-name", required_argument, nullptr, 'n'},
    {nullptr, 0, nullptr, 0}
};

static const std::string SHORT_OPTIONS_PERM = "hg::c::i:p:";
static const struct option LONG_OPTIONS_PERM[] = {
    {"help", no_argument, nullptr, 'h'},
    {"grant", no_argument, nullptr, 'g'},
    {"cancel", no_argument, nullptr, 'c'},
    {"token-id", required_argument, nullptr, 'i'},
    {"permission-name", required_argument, nullptr, 'p'},
    {nullptr, 0, nullptr, 0}
};
}

AtmCommand::AtmCommand(int32_t argc, char *argv[]) : argc_(argc), argv_(argv), name_(TOOLS_NAME)
{
    opterr = 0;

    commandMap_ = {
        {"help", std::bind(&AtmCommand::RunAsHelpCommand, this)},
        {"dump", std::bind(&AtmCommand::RunAsCommonCommand, this)},
        {"perm", std::bind(&AtmCommand::RunAsCommonCommand, this)},
    };

    if ((argc < MIN_ARGUMENT_NUMBER) || (argc > MAX_ARGUMENT_NUMBER)) {
        cmd_ = "help";

        return;
    }

    cmd_ = argv[1];

    for (int32_t i = 2; i < argc; i++) {
        argList_.push_back(argv[i]);
    }
}

std::string AtmCommand::GetCommandErrorMsg() const
{
    std::string commandErrorMsg =
        name_ + ": '" + cmd_ + "' is not a valid " + name_ + " command. See '" + name_ + " help'.\n";

    return commandErrorMsg;
}

std::string AtmCommand::ExecCommand()
{
    auto respond = commandMap_[cmd_];
    if (respond == nullptr) {
        resultReceiver_.append(GetCommandErrorMsg());
    } else {
        respond();
    }

    return resultReceiver_;
}

int32_t AtmCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);

    return RET_SUCCESS;
}

int32_t AtmCommand::RunAsCommandError(void)
{
    int32_t result = RET_SUCCESS;

    if ((optind < 0) || (optind >= argc_)) {
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

std::string AtmCommand::GetUnknownOptionMsg() const
{
    std::string result;

    if ((optind < 0) || (optind > argc_)) {
        return result;
    }

    result.append("error: unknown option\n.");

    return result;
}

int32_t AtmCommand::RunAsCommandMissingOptionArgument(void)
{
    int32_t result = RET_SUCCESS;
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
            std::string unknownOptionMsg = GetUnknownOptionMsg();

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }
    return result;
}

int32_t AtmCommand::RunAsCommandExistentOptionArgument(const int32_t& option, AtmToolsParamInfo& info)
{
    int32_t result = RET_SUCCESS;
    switch (option) {
        case 'h':
            // 'atm dump -h'
            result = ERR_INVALID_VALUE;
            break;
        case 't':
            info.type = DUMP_TOKEN;
            break;
        case 'r':
            info.type = DUMP_RECORD;
            break;
        case 'g':
            info.type = PERM_GRANT;
            break;
        case 'c':
            info.type = PERM_REVOKE;
            break;
        case 'i':
            if (optarg != nullptr) {
                info.tokenId = static_cast<AccessTokenID>(std::atoi(optarg));
            }
            break;
        case 'p':
            if (optarg != nullptr) {
                info.permissionName = optarg;
            }
            break;
        case 'b':
            if (optarg != nullptr) {
                info.bundleName = optarg;
            }
            break;
        case 'n':
            if (optarg != nullptr) {
                info.processName = optarg;
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

int32_t AtmCommand::ModifyPermission(const OptType& type, AccessTokenID tokenId, const std::string& permissionName)
{
    if ((tokenId == 0) || (permissionName.empty())) {
        return ERR_INVALID_VALUE;
    }

    int32_t result = 0;
    if (type == PERM_GRANT) {
        result = AccessTokenKit::GrantPermission(tokenId, permissionName, PERMISSION_USER_FIXED);
    } else if (type == PERM_REVOKE) {
        result = AccessTokenKit::RevokePermission(tokenId, permissionName, PERMISSION_USER_FIXED);
    } else {
        return ERR_INVALID_VALUE;
    }
    return result;
}

int32_t AtmCommand::RunCommandByOperationType(const AtmToolsParamInfo& info)
{
    std::string dumpInfo;
    int32_t ret = RET_SUCCESS;
    switch (info.type) {
        case DUMP_TOKEN:
            AccessTokenKit::DumpTokenInfo(info, dumpInfo);
            break;
        case DUMP_RECORD:
            dumpInfo = DumpRecordInfo(info.tokenId, info.permissionName);
            break;
        case PERM_GRANT:
        case PERM_REVOKE:
            ret = ModifyPermission(info.type, info.tokenId, info.permissionName);
            if (ret == RET_SUCCESS) {
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

int32_t AtmCommand::HandleComplexCommand(const std::string& shortOption, const struct option longOption[],
    const std::string& helpMsg)
{
    int32_t result = RET_SUCCESS;
    AtmToolsParamInfo info;
    int32_t counter = 0;

    while (true) {
        counter++;
        int32_t option = getopt_long(argc_, argv_, shortOption.c_str(), longOption, nullptr);
        if ((optind < 0) || (optind > argc_)) {
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

        result = RunAsCommandExistentOptionArgument(option, info);
    }

    if (result != RET_SUCCESS) {
        resultReceiver_.append(helpMsg + "\n");
    } else {
        result = RunCommandByOperationType(info);
    }
    return result;
}

int32_t AtmCommand::RunAsCommonCommand()
{
    if (cmd_ == "dump") {
        return HandleComplexCommand(SHORT_OPTIONS_DUMP, LONG_OPTIONS_DUMP, HELP_MSG_DUMP);
    } else if (cmd_ == "perm") {
        return HandleComplexCommand(SHORT_OPTIONS_PERM, LONG_OPTIONS_PERM, HELP_MSG_PERM);
    }

    return ERR_PARAM_INVALID;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
