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

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "base_remote_command.h"
#include "constant_common.h"
#include "device_info.h"
#include "device_info_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

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
    CJsonUnique jsonObject = CreateJsonFromString(json);
    if (jsonObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonObject is invalid.");
        return;
    }
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject.get());
    uint32_t tokenId;
    if (GetUnsignedIntFromJson(jsonObject, "tokenId", tokenId)) {
        deleteTokenId_ = (AccessTokenID)tokenId;
    }
}

std::string DeleteRemoteTokenCommand::ToJsonPayload()
{
    CJsonUnique j = BaseRemoteCommand::ToRemoteProtocolJson();
    if (j == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "J is invalid.");
        return "";
    }
    AddUnsignedIntToJson(j, "tokenId", deleteTokenId_);
    return PackJsonToString(j);
}

void DeleteRemoteTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    LOGI(ATM_DOMAIN, ATM_TAG, "End as: DeleteRemoteTokenCommand");
}

void DeleteRemoteTokenCommand::Execute()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: start as: DeleteRemoteTokenCommand");
    remoteProtocol_.responseDeviceId = ConstantCommon::GetLocalDeviceId();
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;

    DeviceInfo devInfo;
    bool result = DeviceInfoManager::GetInstance().GetDeviceInfo(remoteProtocol_.srcDeviceId,
        DeviceIdType::UNKNOWN, devInfo);
    if (!result) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Error: get remote uniqueDeviceId failed");
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

    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: end as: DeleteRemoteTokenCommand");
}

void DeleteRemoteTokenCommand::Finish()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    LOGI(ATM_DOMAIN, ATM_TAG, "Finish: end as: DeleteUidPermissionCommand");
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

