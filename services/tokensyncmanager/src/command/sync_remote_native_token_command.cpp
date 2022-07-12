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

#include "sync_remote_native_token_command.h"

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "base_remote_command.h"
#include "constant_common.h"
#include "device_info_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SyncRemoteNativeTokenCommand"};
}

SyncRemoteNativeTokenCommand::SyncRemoteNativeTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId)
{
    remoteProtocol_.commandName = COMMAND_NAME;
    remoteProtocol_.uniqueId = COMMAND_NAME;
    remoteProtocol_.srcDeviceId = srcDeviceId;
    remoteProtocol_.dstDeviceId = dstDeviceId;
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    remoteProtocol_.requestVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
}

SyncRemoteNativeTokenCommand::SyncRemoteNativeTokenCommand(const std::string &json)
{
    nlohmann::json jsonObject = nlohmann::json::parse(json, nullptr, false);
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject);

    if (jsonObject.find("NativeTokenInfos") != jsonObject.end() && jsonObject.at("NativeTokenInfos").is_array()) {
        nlohmann::json nativeTokenListJson = jsonObject.at("NativeTokenInfos");
        for (const auto& tokenJson : nativeTokenListJson) {
            NativeTokenInfoForSync token;
            BaseRemoteCommand::FromNativeTokenInfoJson(tokenJson, token);
            nativeTokenInfo_.emplace_back(token);
        }
    }
}

std::string SyncRemoteNativeTokenCommand::ToJsonPayload()
{
    nlohmann::json j = BaseRemoteCommand::ToRemoteProtocolJson();
    nlohmann::json nativeTokensJson;
    for (const auto& token : nativeTokenInfo_) {
        nlohmann::json tokenJson = BaseRemoteCommand::ToNativeTokenInfoJson(token);
        nativeTokensJson.emplace_back(tokenJson);
    }
    j["NativeTokenInfos"] = nativeTokensJson;
    return j.dump();
}

void SyncRemoteNativeTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "end as: SyncRemoteNativeTokenCommand");
}

void SyncRemoteNativeTokenCommand::Execute()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "execute: start as: SyncRemoteNativeTokenCommand");
    remoteProtocol_.responseDeviceId = ConstantCommon::GetLocalDeviceId();
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;

    int ret = AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfo_);
    if (ret != RET_SUCCESS) {
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        remoteProtocol_.message = Constant::COMMAND_RESULT_FAILED;
    } else {
        remoteProtocol_.statusCode = Constant::SUCCESS;
        remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "execute: end as: SyncRemoteNativeTokenCommand");
}

void SyncRemoteNativeTokenCommand::Finish()
{
    if (remoteProtocol_.statusCode != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Finish: end as: SyncRemoteHapTokenCommand get remote result error.");
        return;
    }

    DeviceInfo devInfo;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(remoteProtocol_.dstDeviceId,
        DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SyncRemoteNativeTokenCommand: get remote uniqueDeviceId failed");
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        return;
    }
    int ret = AccessTokenKit::SetRemoteNativeTokenInfo(devInfo.deviceId.uniqueDeviceId, nativeTokenInfo_);
    if (ret == RET_SUCCESS) {
        remoteProtocol_.statusCode = Constant::SUCCESS;
    } else {
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Finish: end as: SyncRemoteNativeTokenCommand ret %{public}d", ret);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

