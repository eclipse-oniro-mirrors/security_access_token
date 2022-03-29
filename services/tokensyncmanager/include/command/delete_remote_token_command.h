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

#ifndef DELETE_REMOTE_TOKEN_COMMAND_H
#define DELETE_REMOTE_TOKEN_COMMAND_H

#include "base_remote_command.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * Command which used to get all native token info from other device.
 */
class DeleteRemoteTokenCommand : public BaseRemoteCommand {
public:
    void Prepare() override;

    void Execute() override;

    void Finish() override;

    std::string ToJsonPayload() override;

    explicit DeleteRemoteTokenCommand(const std::string &json);
    DeleteRemoteTokenCommand(const std::string &srcDeviceId, const std::string &dstDeviceId,
        AccessTokenID deleteID);
    virtual ~DeleteRemoteTokenCommand() = default;

private:
    /**
     * The command name. Should be equal to class name.
     */
    const std::string COMMAND_NAME = "DeleteRemoteTokenCommand";
    AccessTokenID deleteTokenId_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif