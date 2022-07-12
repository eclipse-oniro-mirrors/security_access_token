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

#include "delete_remote_token_command.h"

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "base_remote_command.h"
#include "constant_common.h"
#include "device_info.h"
#include "device_info_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DeleteRemoteTokenCommand"};
}

DeleteRemoteTokenCommand::DeleteRemoteTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, AccessTokenID deleteID)
    : deleteTokenId_(deleteID)
{
    remoteProtocol_.commandName = COMMAND_NAME;
    remoteProtocol_.uniqueId = COMMAND_NAME;
    remoteProtocol_.srcDeviceId = srcDeviceId;
    remoteProtocol_.dstDeviceId = dstDeviceId;
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    remoteProtocol_.requestVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
}

DeleteRemoteTokenCommand::DeleteRemoteTokenCommand(const std::string& json)
{
    deleteTokenId_ = 0;
    nlohmann::json jsonObject = nlohmann::json::parse(json, nullptr, false);
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject);

    if (jsonObject.find("tokenId") != jsonObject.end() && jsonObject.at("tokenId").is_number()) {
        deleteTokenId_ = (AccessTokenID)jsonObject.at("tokenId").get<int>();
    }
}

std::string DeleteRemoteTokenCommand::ToJsonPayload()
{
    nlohmann::json j = BaseRemoteCommand::ToRemoteProtocolJson();
    if (j.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "j is invalid.");
        return "";
    }
    j["tokenId"] = deleteTokenId_;
    return j.dump();
}

void DeleteRemoteTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    ACCESSTOKEN_LOG_INFO(LABEL, "end as: DeleteRemoteTokenCommand");
}

void DeleteRemoteTokenCommand::Execute()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "execute: start as: DeleteRemoteTokenCommand");
    remoteProtocol_.responseDeviceId = ConstantCommon::GetLocalDeviceId();
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;

    DeviceInfo devInfo;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(remoteProtocol_.srcDeviceId,
        DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        ACCESSTOKEN_LOG_INFO(LABEL, "error: get remote uniqueDeviceId failed");
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        return;
    }

    std::string uniqueDeviceId = devInfo.deviceId.uniqueDeviceId;
    int ret = AccessTokenKit::DeleteRemoteToken(uniqueDeviceId, deleteTokenId_);
    if (ret != RET_SUCCESS) {
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        remoteProtocol_.message = Constant::COMMAND_RESULT_FAILED;
    } else {
        remoteProtocol_.statusCode = Constant::SUCCESS;
        remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "execute: end as: DeleteRemoteTokenCommand");
}

void DeleteRemoteTokenCommand::Finish()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    ACCESSTOKEN_LOG_INFO(LABEL, "Finish: end as: DeleteUidPermissionCommand");
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

