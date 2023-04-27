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

#ifndef ACCESSTOKENMANAGER_COMMAND_H
#define ACCESSTOKENMANAGER_COMMAND_H

#include <cstdint>
#include <functional>
#include <getopt.h>
#include <map>
#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef enum TypeOptType {
    DEFAULT = 0,
    DUMP_TOKEN,
    DUMP_RECORD,
    PERM_GRANT,
    PERM_REVOKE,
} OptType;

class AtmCommand final {
public:
    AtmCommand(int32_t argc, char *argv[]);
    virtual ~AtmCommand() = default;

    std::string ExecCommand();

private:
    std::string GetCommandErrorMsg() const;
    int32_t RunAsCommandError(void);
    std::string GetUnknownOptionMsg() const;
    int32_t RunAsCommandMissingOptionArgument(void);
    int32_t RunAsCommandExistentOptionArgument(const int32_t& option,
        OptType& type, AccessTokenID tokenId, std::string& permissionName);
    std::string DumpRecordInfo(uint32_t tokenId, const std::string& permissionName);
    int32_t ModifyPermission(const OptType& type, AccessTokenID tokenId, const std::string& permissionName);
    int32_t RunCommandByOperationType(const OptType& type,
        AccessTokenID tokenId, const std::string& permissionName);
    int32_t HandleComplexCommand(const std::string& shortOption, const struct option longOption[],
        const std::string& helpMsg);

    int32_t RunAsHelpCommand();
    int32_t RunAsCommonCommand();

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
