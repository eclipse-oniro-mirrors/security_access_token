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
const std::string TOOLS_NAME = "atm";
const std::string HELP_MSG = "usage: atm <command> <option>\n"
                             "These are common atm commands list:\n"
                             "  help    list available commands\n"
                             "  dump    dump token info\n";

const std::string HELP_MSG_DUMP =
    "usage: atm dump <option>.\n"
    "options list:\n"
    "  -h, --help                                       list available options\n"
    "  -t, --token-info                                 list all token info in system\n"
    "  -r [-b <bundle-name>] [-p <permission-name>]     list used records in system\n";

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

    ErrCode RunAsDumpCommandError(void);
    ErrCode RunAsDumpCommandMissingOptionArgument(void);
    ErrCode RunAsDumpCommandExistentOptionArgument(const int &option,
        bool &isDumpTokenInfo, bool &isDumpRecordInfo, uint32_t& tokenId, std::string& permissionName);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKENMANAGER_COMMAND_H
