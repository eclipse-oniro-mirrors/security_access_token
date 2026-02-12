/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include <map>
#include <sstream>
#include <string>

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "native_token_info.h"
#include "permission_status.h"
#include "privacy_kit.h"
#include "to_string.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t MAX_COUNTER = 1000;
static constexpr int32_t MIN_ARGUMENT_NUMBER = 2;
static constexpr int32_t MAX_ARGUMENT_NUMBER = 4096;
static const std::string HELP_MSG_NO_OPTION = "Error: you must specify an option at least.\n";
static const std::string SHORT_OPTIONS_DUMP = "d::h::t::r::v::i:p:b:n:";
static const std::string TOOLS_NAME = "atm";
static const std::string HELP_MSG =
    "usage: atm <command> <option>\n"
    "These are common atm commands list:\n"
    "  help    list available commands\n"
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "  perm    grant/cancel permission\n"
    "  toggle  set/get toggle request/record status\n"
#endif
    "  dump    dump system command\n";

static const std::string HELP_MSG_DUMP =
    "usage: atm dump <option>.\n"
    "options list:\n"
    "  -h, --help                                               list available options\n"
    "  -d, --definition [-p <permission-name>]                  list all permission definitions in system\n"
    "  -t, --all                                                list all name of token info in system\n"
    "  -t, --token-info -i <token-id>                           list single token info by specific tokenId\n"
    "  -t, --token-info -b <bundle-name>                        list all token info by specific bundleName\n"
    "  -t, --token-info -n <process-name>                       list single token info by specific native processName\n"
    "  -t, --token -p <permission-name>                         list apps by permission (TokenID and BundleName)\n"
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "  -r, --record-info [-i <token-id>] [-p <permission-name>] list used records in system\n"
    "  -v, --visit-type [-i <token-id>] [-p <permission-name>]  list all token used type in system\n";
#else
    "";
#endif

static const std::string HELP_MSG_PERM =
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "usage: atm perm <option>.\n"
    "options list:\n"
    "  -h, --help                                       list available options\n"
    "  -g, --grant -i <token-id> -p <permission-name>   grant a permission by a specified token-id\n"
    "  -c, --cancel -i <token-id> -p <permission-name>  cancel a permission by a specified token-id\n";
#else
    "";
#endif

static const std::string HELP_MSG_TOGGLE =
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "usage: atm toggle request <option>.\n"
    "options list:\n"
    "  -h, --help                                                  list available options\n"
    "  -r -s, --set -i <user-id> -p <permission-name> -k <status>  set request status by specified user-id and perm\n"
    "  -r -o, --get -i <user-id> -p <permission-name>              get request status by specified user-id and perm\n"
    "  -u -s, --set -i <user-id> -k <status>                       set record status by a specified user-id\n"
    "  -u -o, --get -i <user-id>                                   get record status by a specified user-id\n"
    "  <status>                                                    0 is closed, 1 is open\n";
#else
    "";
#endif

static const std::string HELP_MSG_TOGGLE_REQUEST =
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "usage: atm toggle request <option>.\n"
    "options list:\n"
    "  -h, --help                                                  list available options\n"
    "  -s, --set -i <user-id> -p <permission-name> -k <status>     set request status by specified user-id and perm\n"
    "  -o, --get -i <user-id> -p <permission-name>                 get request status by specified user-id and perm\n"
    "  <status>                                                    0 is closed, 1 is open\n";
#else
    "";
#endif

static const std::string HELP_MSG_TOGGLE_RECORD =
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    "usage: atm toggle record <option>.\n"
    "options list:\n"
    "  -h, --help                                                  list available options\n"
    "  -s, --set -i <user-id> -k <status>                          set record status by a specified user-id\n"
    "  -o, --get -i <user-id>                                      get record status by a specified user-id\n"
    "  <status>                                                    0 is closed, 1 is open\n";
#else
    "";
#endif

static const struct option LONG_OPTIONS_DUMP[] = {
    {"definition", no_argument, nullptr, 'd'},
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

// required option
static const std::vector<char> REQUIRED_OPTIONS_DUMP = {'b', 'i', 'n', 'p'};
static const std::vector<char> REQUIRED_OPTIONS_PERM = {'g', 'c', 'i', 'p'};
static const std::vector<char> REQUIRED_OPTIONS_TOGGLE = {'i', 'k', 'p'};

static const std::string SHORT_OPTIONS_TOGGLE = "hr::u::s::o::i:p:k:";
static const struct option LONG_OPTIONS_TOGGLE[] = {
    {"help", no_argument, nullptr, 'h'},
    {"request", no_argument, nullptr, 'r'},
    {"record", no_argument, nullptr, 'u'},
    {"set", no_argument, nullptr, 's'},
    {"get", no_argument, nullptr, 'o'},
    {"user-id", required_argument, nullptr, 'i'},
    {"permission-name", required_argument, nullptr, 'p'},
    {"status", required_argument, nullptr, 'k'},
    {nullptr, 0, nullptr, 0}
};

std::map<char, OptType> DUMP_COMMAND_TYPE = {
    // dump
    {'d', DUMP_PERM},
    {'t', DUMP_TOKEN},
    {'r', DUMP_RECORD},
    {'v', DUMP_TYPE},
};

std::map<char, ToggleModeType> TOGGLE_MODE_TYPE = {
    {'r', TOGGLE_REQUEST},
    {'u', TOGGLE_RECORD},
};
std::map<char, ToggleOperateType> TOGGLE_OPERATE_TYPE = {
    {'s', TOGGLE_SET},
    {'o', TOGGLE_GET},
};
}

AtmCommand::AtmCommand(int32_t argc, char* argv[]) : argc_(argc), argv_(argv), name_(TOOLS_NAME)
{
    optind = 1;
    opterr = 0;

    commandMap_ = {
        {"help", [this](){return RunAsHelpCommand();}},
        {"dump", [this]() {return RunAsCommonCommandForDump();}},
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
        {"perm", [this]() {return RunAsCommonCommandForPerm();}},
        {"toggle", [this]() {return RunAsCommonCommandForToggle();}},
#endif
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
    auto it = commandMap_.find(cmd_);
    if (it == commandMap_.end() || !it->second) {
        resultReceiver_.append(GetCommandErrorMsg());
    } else {
        it->second();
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

    result.append("Error: Unknown option.\n");

    return result;
}

int32_t AtmCommand::RunAsCommandMissingOptionArgument(const std::vector<char>& requiredOptions)
{
    if (optopt == 'h') {
        return ERR_INVALID_VALUE;
    }
    auto iter = std::find(requiredOptions.begin(), requiredOptions.end(), optopt);
    if (iter == requiredOptions.end()) {
        resultReceiver_.append(GetUnknownOptionMsg());
        return ERR_INVALID_VALUE;
    }
    resultReceiver_.append("Error: Option requires a value.\n\n");
    return ERR_INVALID_VALUE;
}

void AtmCommand::RunAsCommandExistentOptionForDump(int32_t option, DumpOptionsContext& context)
{
    switch (option) {
        case 'd':
        case 'r':
        case 'v':
            context.type = DUMP_COMMAND_TYPE[option];
            break;
        case 't':
            context.hasTokenOption = true;
            break;
        case 'i':
            context.hasTokenIdOption = true;
            if (optarg != nullptr && optarg[0] != '\0') {
                context.info.tokenId = static_cast<AccessTokenID>(std::atoi(optarg));
            }
            break;
        case 'p':
            context.hasPermissionOption = true;
            if (optarg != nullptr && optarg[0] != '\0') {
                context.permissionName = optarg;
            }
            break;
        case 'b':
            if (optarg != nullptr && optarg[0] != '\0') {
                context.info.bundleName = optarg;
            }
            break;
        case 'n':
            if (optarg != nullptr && optarg[0] != '\0') {
                context.info.processName = optarg;
            }
            break;
        default:
            break;
    }
}

void AtmCommand::RunAsCommandExistentOptionForPerm(int32_t option, PermOptionsContext& context)
{
    switch (option) {
        case 'g':
            context.isGranted = true;
            break;
        case 'c':
            context.isGranted = false;
            break;
        case 'i':
            context.hasTokenIdOption = true;
            context.tokenID = (optarg != nullptr) ? static_cast<AccessTokenID>(std::atoi(optarg)) : INVALID_TOKENID;
            break;
        case 'p':
            context.hasPermissionOption = true;
            context.permission = (optarg != nullptr && optarg[0] != '\0') ? optarg : "";
            break;
        default:
            break;
        }
}

void AtmCommand::RunAsCommandExistentOptionForToggle(int32_t option, AtmToggleParamInfo& info)
{
    switch (option) {
        case 'r':
        case 'u':
            info.toggleMode = TOGGLE_MODE_TYPE[option];
            break;
        case 's':
        case 'o':
            info.type = TOGGLE_OPERATE_TYPE[option];
            break;
        case 'p':
            info.permissionName = (optarg != nullptr) ? optarg : "";;
            break;
        case 'i':
            if (optarg != nullptr) {
                if (IsNumericString(optarg)) {
                    info.userID = static_cast<int32_t>(std::atoi(optarg));
                } else {
                    info.userID = -1;
                }
            }
            break;
        case 'k':
            if (optarg != nullptr && (strcmp(optarg, "0") == 0 || strcmp(optarg, "1") == 0)) {
                info.status = static_cast<uint32_t>(std::atoi(optarg));
            }
            break;
        default:
            break;
    }
}

bool AtmCommand::IsNumericString(const char* string)
{
    if (string == nullptr || string[0] == '\0') {
        return false;
    }

    for (int32_t i = 0; string[i] != '\0'; i++) {
        if (!isdigit(string[i])) {
            return false;
        }
    }

    return true;
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

    return ToString::PermissionUsedResultToString(result);
}

std::string AtmCommand::DumpUsedTypeInfo(uint32_t tokenId, const std::string& permissionName)
{
    std::vector<PermissionUsedTypeInfo> results;
    if (PrivacyKit::GetPermissionUsedTypeInfos(tokenId, permissionName, results) != 0) {
        return "";
    }

    return ToString::PermissionUsedTypeInfoToString(results);
}

std::string AtmCommand::DumpPermissionApps(const std::string& permissionName)
{
    if (permissionName.empty()) {
        return "Error: Permission name cannot be empty.\n"
               "Usage: atm dump -t -p <permission-name>\n"
               "Example: atm dump -t -p ohos.permission.CAMERA";
    }

    // Query all applications that have requested the specified permission
    std::vector<std::string> permissionList = {permissionName};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, true);
    if (ret != RET_SUCCESS) {
        return "Error: Permission '" + permissionName + "' does not exist.";
    }

    // Format output
    std::stringstream ss;
    ss << "Permission: " << permissionName << "\n";
    ss << "Total Tokens: " << permissionInfoList.size() << "\n\n";

    if (permissionInfoList.empty()) {
        return ss.str();
    }

    // Group by tokenID and extract bundle name/process name
    std::map<AccessTokenID, std::string> appMap;
    for (const auto& info : permissionInfoList) {
        if (appMap.find(info.tokenID) != appMap.end()) {
            continue;
        }
        HapTokenInfo hapInfo;
        (void)AccessTokenKit::GetHapTokenInfo(info.tokenID, hapInfo);
        appMap[info.tokenID] = hapInfo.bundleName;
    }

    // Output in format: tokenId: bundleName/processName (same as "atm dump -t")
    for (const auto& entry : appMap) {
        ss << entry.first << ": " << entry.second << "\n";
    }

    return ss.str();
}

int32_t AtmCommand::ModifyPermission(bool isGranted, AccessTokenID tokenId, const std::string& permissionName)
{
    int32_t result = 0;
    if (isGranted) {
        result = AccessTokenKit::GrantPermission(tokenId, permissionName, PERMISSION_USER_FIXED);
    } else {
        result = AccessTokenKit::RevokePermission(tokenId, permissionName, PERMISSION_USER_FIXED);
    }
    return result;
}

int32_t AtmCommand::SetToggleStatus(int32_t userID, const std::string& permissionName, const uint32_t& status)
{
    if ((userID < 0) || (permissionName.empty()) ||
        ((status != PermissionRequestToggleStatus::OPEN) &&
         (status != PermissionRequestToggleStatus::CLOSED))) {
        return ERR_INVALID_VALUE;
    }

    return AccessTokenKit::SetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AtmCommand::GetToggleStatus(int32_t userID, const std::string& permissionName, std::string& statusInfo)
{
    if ((userID < 0) || (permissionName.empty())) {
        return ERR_INVALID_VALUE;
    }

    uint32_t status;
    int32_t result = AccessTokenKit::GetPermissionRequestToggleStatus(permissionName, status, userID);
    if (result != RET_SUCCESS) {
        return result;
    }

    if (status == PermissionRequestToggleStatus::OPEN) {
        statusInfo = "Toggle status is open";
    } else {
        statusInfo = "Toggle status is closed";
    }

    return result;
}

int32_t AtmCommand::RunCommandByOperationType(const AtmToolsParamInfo& info, OptType type, std::string& permissionName)
{
    std::string dumpInfo;
    int32_t ret = RET_SUCCESS;
    switch (type) {
        case DUMP_PERM:
            dumpInfo = ToString::DumpPermDefinition(permissionName);
            break;
        case DUMP_TOKEN:
            AccessTokenKit::DumpTokenInfo(info, dumpInfo);
            break;
        case DUMP_PERMISSION_APPS:
            dumpInfo = DumpPermissionApps(permissionName);
            break;
        case DUMP_RECORD:
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
            dumpInfo = DumpRecordInfo(info.tokenId, permissionName);
            break;
        case DUMP_TYPE:
            dumpInfo = DumpUsedTypeInfo(info.tokenId, permissionName);
            break;
#endif
        default:
            resultReceiver_.append("Error: Missing option.\n");
            return ERR_INVALID_VALUE;
    }
    resultReceiver_.append(dumpInfo + "\n");
    return ret;
}

int32_t AtmCommand::SetRecordToggleStatus(int32_t userID, const uint32_t& recordStatus, std::string& statusInfo)
{
    if ((userID < 0)) {
        statusInfo = "Invalid userID\n";
        return ERR_INVALID_VALUE;
    }

    if ((recordStatus != 0) && (recordStatus != 1)) {
        statusInfo = "Invalid status\n";
        return ERR_INVALID_VALUE;
    }

    bool status = (recordStatus == 1);

    return PrivacyKit::SetPermissionUsedRecordToggleStatus(userID, status);
}

int32_t AtmCommand::GetRecordToggleStatus(int32_t userID, std::string& statusInfo)
{
    if ((userID < 0)) {
        statusInfo = "Invalid userID\n";
        return ERR_INVALID_VALUE;
    }

    bool status = true;
    int32_t result = PrivacyKit::GetPermissionUsedRecordToggleStatus(userID, status);
    if (result != RET_SUCCESS) {
        return result;
    }

    statusInfo = status ? "Record toggle status is open \n" : "Record toggle status is closed \n";

    return result;
}

int32_t AtmCommand::HandleToggleRequest(const AtmToggleParamInfo& info, std::string& dumpInfo)
{
    int32_t ret = RET_SUCCESS;

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    switch (info.type) {
        case TOGGLE_SET:
            ret = SetToggleStatus(info.userID, info.permissionName, info.status);
            dumpInfo = (ret == RET_SUCCESS) ? "Success" : "Failure";
            break;
        case TOGGLE_GET:
            ret = GetToggleStatus(info.userID, info.permissionName, dumpInfo);
            if (ret != RET_SUCCESS) {
                dumpInfo = "Failure";
            }
            break;
        default:
            resultReceiver_.append("Error: Missing option.\n");
            return ERR_INVALID_VALUE;
        }
#endif

    return ret;
}

int32_t AtmCommand::HandleToggleRecord(const AtmToggleParamInfo& info, std::string& dumpInfo)
{
    int32_t ret = RET_SUCCESS;

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    switch (info.type) {
        case TOGGLE_SET:
            ret = SetRecordToggleStatus(info.userID, info.status, dumpInfo);
            dumpInfo += (ret == RET_SUCCESS) ? "Success" : "Failure";
            break;
        case TOGGLE_GET:
            ret = GetRecordToggleStatus(info.userID, dumpInfo);
            dumpInfo += (ret == RET_SUCCESS) ? "Success" : "Failure";
            break;
        default:
            resultReceiver_.append("Error: Miss option.\n");
            return ERR_INVALID_VALUE;
    }
#endif
    return ret;
}

int32_t AtmCommand::RunToggleCommandByOperationType(const AtmToggleParamInfo& info)
{
    std::string dumpInfo;
    int32_t ret = RET_SUCCESS;

    switch (info.toggleMode) {
        case TOGGLE_REQUEST:
            ret = HandleToggleRequest(info, dumpInfo);
            break;
        case TOGGLE_RECORD:
            ret = HandleToggleRecord(info, dumpInfo);
            break;
        default:
            resultReceiver_.append("Error: Unspecified toggle mode.\n");
            return ERR_INVALID_VALUE;
    }

    resultReceiver_.append(dumpInfo + "\n");
    return ret;
}

static bool IsTokenIdInvalid(const DumpOptionsContext& context)
{
    return context.hasTokenIdOption && context.info.tokenId == 0;
}

static void ResolveDumpOperationType(DumpOptionsContext& context)
{
    if (context.hasTokenOption && context.hasPermissionOption && !context.permissionName.empty()) {
        context.type = DUMP_PERMISSION_APPS;
        return;
    }
    if (context.hasTokenOption && !context.hasPermissionOption) {
        context.type = DUMP_TOKEN;
    }
}

int32_t AtmCommand::RunAsCommonCommandForDump()
{
    int32_t result = RET_SUCCESS;
    DumpOptionsContext context;
    int32_t counter = 0;

    while (true) {
        ++counter;
        int32_t option = getopt_long(argc_, argv_, SHORT_OPTIONS_DUMP.c_str(), LONG_OPTIONS_DUMP, nullptr);
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
            result = RunAsCommandMissingOptionArgument(REQUIRED_OPTIONS_DUMP);
            break;
        }

        if (option == 'h') {
            result = ERR_INVALID_VALUE;
            continue;
        }

        if (optarg != nullptr && optarg[0] == '\0' &&
            (option == 'i' || option == 'p' || option == 'b' || option == 'n')) {
            resultReceiver_.append("Error: Option requires a value.\n\n");
            result = ERR_INVALID_VALUE;
            break;
        }

        RunAsCommandExistentOptionForDump(option, context);
    }

    if (result != RET_SUCCESS) {
        resultReceiver_.append(HELP_MSG_DUMP + "\n");
        return result;
    }

    if (IsTokenIdInvalid(context)) {
        resultReceiver_.append("Error: TokenID is invalid.\n");
        return ERR_INVALID_VALUE;
    }

    ResolveDumpOperationType(context);
    return RunCommandByOperationType(context.info, context.type, context.permissionName);
}

int32_t AtmCommand::RunAsCommonCommandForPerm()
{
    int32_t result = RET_SUCCESS;
    int32_t counter = 0;
    PermOptionsContext context;

    while (true) {
        ++counter;
        int32_t option = getopt_long(argc_, argv_, SHORT_OPTIONS_PERM.c_str(), LONG_OPTIONS_PERM, nullptr);
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
            result = RunAsCommandMissingOptionArgument(REQUIRED_OPTIONS_PERM);
            break;
        }
        if (option == 'h') {
            result = ERR_INVALID_VALUE;
            continue;
        }
        RunAsCommandExistentOptionForPerm(option, context);
    }
    if (result != RET_SUCCESS) {
        resultReceiver_.append(HELP_MSG_PERM + "\n");
        return result;
    }

    // Check if -i parameter is missing
    result = ValidatePermParams(context);
    if (result != RET_SUCCESS) {
        return result;
    }

    result = ModifyPermission(context.isGranted, context.tokenID, context.permission);
    if (result == RET_SUCCESS) {
        resultReceiver_.append("Success\n");
    } else if (result == AccessTokenError::ERR_TOKENID_NOT_EXIST) {
        // TokenID does not exist or is not a valid application TokenID
        resultReceiver_.append("Error: TokenID does not exist or is not a valid application TokenID.\n");
    } else if (result == AccessTokenError::ERR_PERMISSION_NOT_EXIST) {
        // Permission does not exist
        resultReceiver_.append("Error: Permission '" + context.permission + "' does not exist.\n");
    } else {
        resultReceiver_.append("Failure\n");
    }
    return result;
}

int32_t AtmCommand::ValidatePermParams(const PermOptionsContext& context)
{
    if (!context.hasTokenIdOption) {
        resultReceiver_.append("Error: Missing required parameter: -i <token-id>\n");
        resultReceiver_.append(HELP_MSG_PERM + "\n");
        return ERR_INVALID_VALUE;
    }

    if (!context.hasPermissionOption) {
        resultReceiver_.append("Error: Missing required parameter: -p <permission-name>\n");
        resultReceiver_.append(HELP_MSG_PERM + "\n");
        return ERR_INVALID_VALUE;
    }

    if (context.tokenID == 0) {
        resultReceiver_.append("Error: TokenID is invalid.\n");
        return ERR_INVALID_VALUE;
    }

    return RET_SUCCESS;
}

static int32_t ValidateToggleSetParams(const AtmToggleParamInfo& info, std::string& errorMsg)
{
    if (info.toggleMode == TOGGLE_REQUEST) {
        if (info.permissionName.empty()) {
            errorMsg = "Error: Missing required parameter: -p <permission-name>\n\n";
        }
        if (info.userID == 0 && info.status == INVALID_ATM_SET_STATUS) {
            errorMsg = "Error: Missing required parameter: -i <user-id> or -k <status>\n\n";
        }
        errorMsg += HELP_MSG_TOGGLE_REQUEST + "\n";
        return ERR_INVALID_VALUE;
    } else if (info.toggleMode == TOGGLE_RECORD) {
        if (info.userID == 0) {
            errorMsg = "Error: Missing required parameter: -i <user-id>\n\n";
        }
        if (info.status == INVALID_ATM_SET_STATUS) {
            errorMsg = "Error: Missing required parameter: -k <status>\n\n";
        }
        errorMsg += HELP_MSG_TOGGLE_RECORD + "\n";
        return ERR_INVALID_VALUE;
    }
    return RET_SUCCESS;
}

int32_t AtmCommand::RunAsCommonCommandForToggle()
{
    int32_t result = RET_SUCCESS;
    AtmToggleParamInfo info;

    if (argc_ >= 3) {
        if (strcmp(argv_[2], "request") == 0) {
            info.toggleMode = TOGGLE_REQUEST;
        } else if (strcmp(argv_[2], "record") == 0) {
            info.toggleMode = TOGGLE_RECORD;
        }
    }

    int32_t counter = 0;
    while (counter < MAX_COUNTER) {
        ++counter;
        int32_t option = getopt_long(argc_, argv_, SHORT_OPTIONS_TOGGLE.c_str(), LONG_OPTIONS_TOGGLE, nullptr);
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
            result = RunAsCommandMissingOptionArgument(REQUIRED_OPTIONS_TOGGLE);
            break;
        }

        if (option == 'h') {
            result = ERR_INVALID_VALUE;
            continue;
        }
        RunAsCommandExistentOptionForToggle(option, info);
    }

    if (result != RET_SUCCESS) {
        std::string helpMsg = (info.toggleMode == TOGGLE_REQUEST) ? HELP_MSG_TOGGLE_REQUEST :
                              (info.toggleMode == TOGGLE_RECORD) ? HELP_MSG_TOGGLE_RECORD : HELP_MSG_TOGGLE;
        resultReceiver_.append(helpMsg + "\n");
        return result;
    }

    if (info.type == TOGGLE_SET) {
        std::string errorMsg;
        result = ValidateToggleSetParams(info, errorMsg);
        if (result != RET_SUCCESS) {
            resultReceiver_.append(errorMsg);
            return result;
        }
    }

    return RunToggleCommandByOperationType(info);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
