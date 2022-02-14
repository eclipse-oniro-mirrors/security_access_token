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

#ifndef REMOTE_COMMAND_FACTORY_H
#define REMOTE_COMMAND_FACTORY_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "delete_remote_token_command.h"
#include "hap_token_info.h"
#include "sync_remote_hap_token_command.h"
#include "sync_remote_native_token_command.h"
#include "update_remote_hap_token_command.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class RemoteCommandFactory {
public:
    static RemoteCommandFactory &GetInstance();

    std::shared_ptr<SyncRemoteHapTokenCommand> NewSyncRemoteHapTokenCommand(const std::string &srcDeviceId,
        const std::string &dstDeviceId, AccessTokenID tokenID);

    std::shared_ptr<DeleteRemoteTokenCommand> NewDeleteRemoteTokenCommand(const std::string &srcDeviceId,
        const std::string &dstDeviceId, AccessTokenID tokenID);

    std::shared_ptr<UpdateRemoteHapTokenCommand> NewUpdateRemoteHapTokenCommand(const std::string &srcDeviceId,
        const std::string &dstDeviceId, const HapTokenInfoForSync& tokenInfo);

    std::shared_ptr<SyncRemoteNativeTokenCommand> NewSyncRemoteNativeTokenCommand(const std::string &srcDeviceId,
        const std::string &dstDeviceId);

    std::shared_ptr<BaseRemoteCommand> NewRemoteCommandFromJson(
        const std::string &commandName, const std::string &commandJsonString);

private:
    const std::string TAG = "RemoteCommandFactory";
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // REMOTE_COMMAND_FACTORY_H
