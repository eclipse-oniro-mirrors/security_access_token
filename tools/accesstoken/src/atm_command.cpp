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

#include "accesstoken_kit.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
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
        // error + message
        // currently there is no error to use
        // {
        //     AppExecFwk::IStatusReceiver::ERR_USER_REMOVE_FALIED,
        //     "error: user remove failed.",
        // },
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
    int result = OHOS::ERR_OK;
    std::string tokenInfo = "";

    AccessTokenKit::DumpTokenInfo(tokenInfo);
    resultReceiver_ = tokenInfo + "\n";

    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS