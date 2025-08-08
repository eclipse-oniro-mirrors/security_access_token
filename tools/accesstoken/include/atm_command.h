/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKENMANAGER_COMMAND_H
#define ACCESSTOKENMANAGER_COMMAND_H

#include <cstdint>
#include <functional>
#include <getopt.h>
#include <map>
#include <string>
#include <vector>

#include "access_token.h"
#include "atm_tools_param_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr const uint32_t INVALID_ATM_SET_STATUS = 2;
/**
 * @brief Atm tools operate type
 */
typedef enum TypeOptType {
    /** default */
    DEFAULT_OPER = 0,
    /** dump hap or native token info */
    DUMP_TOKEN,
    /** dump permission used records */
    DUMP_RECORD,
    /** dump permission used types */
    DUMP_TYPE,
    /** dump permission definition info */
    DUMP_PERM,
    /** grant permission */
    PERM_GRANT,
    /** revoke permission */
    PERM_REVOKE,
} OptType;

/**
 * @brief Atm toggle mode type
 */
typedef enum TypeToggleModeType {
    /** toggle mode is request */
    TOGGLE_REQUEST = 0,
    /** toggle mode is record */
    TOGGLE_RECORD,
} ToggleModeType;

typedef enum TypeToggleOperateType {
    /** set toggle request/record status */
    TOGGLE_SET,
    /** get toggle request/record status */
    TOGGLE_GET,
} ToggleOperateType;

class AtmToggleParamInfo final {
public:
    ToggleModeType toggleMode;
    ToggleOperateType type;
    int32_t userID;
    std::string permissionName;
    uint32_t status = INVALID_ATM_SET_STATUS;
};

class AtmCommand final {
public:
    AtmCommand(int32_t argc, char *argv[]);
    virtual ~AtmCommand() = default;

    std::string ExecCommand();

private:
    std::string GetCommandErrorMsg() const;
    int32_t RunAsCommandError(void);
    std::string GetUnknownOptionMsg() const;
    int32_t RunAsCommandMissingOptionArgument(const std::vector<char>& requeredOptions);
    void RunAsCommandExistentOptionForDump(
        const int32_t& option, AtmToolsParamInfo& info, OptType& type, std::string& permissionName);
    void RunAsCommandExistentOptionForPerm(
        const int32_t& option, bool& isGranted, AccessTokenID& tokenID, std::string& permission);
    void RunAsCommandExistentOptionForToggle(const int32_t& option, AtmToggleParamInfo& info);
    std::string DumpRecordInfo(uint32_t tokenId, const std::string& permissionName);
    std::string DumpUsedTypeInfo(uint32_t tokenId, const std::string& permissionName);
    int32_t ModifyPermission(bool isGranted, AccessTokenID tokenId, const std::string& permissionName);
    int32_t RunCommandByOperationType(const AtmToolsParamInfo& info, OptType type, std::string& permissionName);

    int32_t SetToggleStatus(int32_t userID, const std::string& permissionName, const uint32_t& status);
    int32_t GetToggleStatus(int32_t userID, const std::string& permissionName, std::string& statusInfo);

    int32_t RunToggleCommandByOperationType(const AtmToggleParamInfo& info);
    int32_t HandleToggleRequest(const AtmToggleParamInfo& info, std::string& dumpInfo);
    int32_t HandleToggleRecord(const AtmToggleParamInfo& info, std::string& dumpInfo);
    int32_t SetRecordToggleStatus(int32_t userID, const uint32_t& recordStatus, std::string& statusInfo);
    int32_t GetRecordToggleStatus(int32_t userID, std::string& statusInfo);
    bool IsNumericString(const char* string);

    int32_t RunAsHelpCommand();
    int32_t RunAsCommonCommandForDump();
    int32_t RunAsCommonCommandForPerm();
    int32_t RunAsCommonCommandForToggle();

    int32_t argc_;
    char** argv_;

    std::string cmd_;
    std::vector<std::string> argList_;

    std::string name_;
    std::map<std::string, std::function<int32_t()>> commandMap_;

    std::string resultReceiver_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKENMANAGER_COMMAND_H
