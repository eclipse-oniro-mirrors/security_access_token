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

#include "shell_command.h"

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

class AtmCommand : public OHOS::AAFwk::ShellCommand {
public:
    AtmCommand(int argc, char *argv[]);
    ~AtmCommand() override
    {}

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode init() override;

    ErrCode RunAsHelpCommand();
    ErrCode RunAsDumpCommand();
    ErrCode RunAsPermCommand();

    ErrCode RunAsCommandError(void);
    ErrCode RunAsCommandExistentOptionArgument(const int& option,
        OptType& type, uint32_t& tokenId, std::string& permissionName);
    ErrCode RunCommandByOperationType(const OptType& type,
        uint32_t& tokenId, std::string& permissionName);

    ErrCode RunAsCommandMissingOptionArgument(void);
    ErrCode ModifyPermission(const OptType& type, uint32_t& tokenId, std::string& permissionName);

    std::string DumpRecordInfo(uint32_t tokenId, const std::string& permissionName);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKENMANAGER_COMMAND_H
