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

#ifndef SYNC_REMOTE_NATIVE_TOKEN_COMMAND_H
#define SYNC_REMOTE_NATIVE_TOKEN_COMMAND_H

#include <string>
#include <vector>

#include "base_remote_command.h"
#include "native_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * Command which used to get all native token info from other device.
 */
class SyncRemoteNativeTokenCommand : public BaseRemoteCommand {
public:
    void Prepare() override;

    void Execute() override;

    void Finish() override;

    std::string ToJsonPayload() override;

    explicit SyncRemoteNativeTokenCommand(const std::string &json);
    SyncRemoteNativeTokenCommand(const std::string &srcDeviceId, const std::string &dstDeviceId);
    virtual ~SyncRemoteNativeTokenCommand() override = default;

private:
    /**
     * The command name. Should be equal to class name.
     */
    const std::string COMMAND_NAME = "SyncRemoteNativeTokenCommand";
    std::vector<NativeTokenInfoForSync> nativeTokenInfo_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif
