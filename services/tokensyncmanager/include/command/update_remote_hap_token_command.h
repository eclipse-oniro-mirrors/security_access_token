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

#ifndef UPDATE_REMOTE_HAP_TOKEN_COMMAND_H
#define UPDATE_REMOTE_HAP_TOKEN_COMMAND_H

#include <string>

#include "access_token.h"
#include "base_remote_command.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * Command which used to get all native token info from other device.
 */
class UpdateRemoteHapTokenCommand : public BaseRemoteCommand {
public:
    void Prepare() override;

    void Execute() override;

    void Finish() override;

    std::string ToJsonPayload() override;

    explicit UpdateRemoteHapTokenCommand(const std::string &json);
    UpdateRemoteHapTokenCommand(const std::string &srcDeviceId, const std::string &dstDeviceId,
        const HapTokenInfoForSync& tokenInfo);
    virtual ~UpdateRemoteHapTokenCommand() override = default;

private:
    /**
     * The command name. Should be equal to class name.
     */
    const std::string COMMAND_NAME = "UpdateRemoteHapTokenCommand";
    HapTokenInfoForSync updateTokenInfo_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif
