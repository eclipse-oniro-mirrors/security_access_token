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

#include "remote_command_factory.h"

#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace AccessToken {
RemoteCommandFactory &RemoteCommandFactory::GetInstance()
{
    static RemoteCommandFactory instance;
    return instance;
}

std::shared_ptr<SyncRemoteHapTokenCommand> RemoteCommandFactory::NewSyncRemoteHapTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, AccessTokenID tokenID)
{
    return std::make_shared<SyncRemoteHapTokenCommand>(srcDeviceId, dstDeviceId, tokenID);
}

std::shared_ptr<DeleteRemoteTokenCommand> RemoteCommandFactory::NewDeleteRemoteTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, AccessTokenID tokenID)
{
    return std::make_shared<DeleteRemoteTokenCommand>(srcDeviceId, dstDeviceId, tokenID);
}

std::shared_ptr<UpdateRemoteHapTokenCommand> RemoteCommandFactory::NewUpdateRemoteHapTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, const HapTokenInfoForSync& tokenInfo)
{
    return std::make_shared<UpdateRemoteHapTokenCommand>(srcDeviceId, dstDeviceId, tokenInfo);
}

std::shared_ptr<SyncRemoteNativeTokenCommand> RemoteCommandFactory::NewSyncRemoteNativeTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId)
{
    return std::make_shared<SyncRemoteNativeTokenCommand>(srcDeviceId, dstDeviceId);
}

std::shared_ptr<BaseRemoteCommand> RemoteCommandFactory::NewRemoteCommandFromJson(
    const std::string &commandName, const std::string &commandJsonString)
{
    const std::string SYNC_HAP_COMMAND_NAME = "SyncRemoteHapTokenCommand";
    const std::string DELETE_TOKEN_COMMAND_NAME = "DeleteRemoteTokenCommand";
    const std::string UPDATE_HAP_COMMAND_NAME = "UpdateRemoteHapTokenCommand";
    const std::string SYNC_NATIVE_COMMAND_NAME = "SyncRemoteNativeTokenCommand";

    if (commandName == SYNC_HAP_COMMAND_NAME) {
        return std::make_shared<SyncRemoteHapTokenCommand>(commandJsonString);
    }
    if (commandName == DELETE_TOKEN_COMMAND_NAME) {
        return std::make_shared<DeleteRemoteTokenCommand>(commandJsonString);
    }
    if (commandName == UPDATE_HAP_COMMAND_NAME) {
        return std::make_shared<UpdateRemoteHapTokenCommand>(commandJsonString);
    }
    if (commandName == SYNC_NATIVE_COMMAND_NAME) {
        return std::make_shared<SyncRemoteNativeTokenCommand>(commandJsonString);
    }
    return nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
