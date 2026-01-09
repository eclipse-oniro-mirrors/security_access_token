/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "update_remote_hap_token_command.h"

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "base_remote_command.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

UpdateRemoteHapTokenCommand::UpdateRemoteHapTokenCommand(
    const std::string& srcDeviceId, const std::string& dstDeviceId, const HapTokenInfoForSync& tokenInfo)
    : updateTokenInfo_(tokenInfo)
{
    remoteProtocol_.commandName = COMMAND_NAME;
    remoteProtocol_.uniqueId = COMMAND_NAME;
    remoteProtocol_.srcDeviceId = srcDeviceId;
    remoteProtocol_.dstDeviceId = dstDeviceId;
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    remoteProtocol_.requestVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    rawDeviceId_ = dstDeviceId;
}

UpdateRemoteHapTokenCommand::UpdateRemoteHapTokenCommand(const std::string& json, const std::string& rawDeviceId)
{
    CJsonUnique jsonObject = CreateJsonFromString(json);
    if (jsonObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonObject is invalid.");
        return;
    }
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject.get());

    CJson* hapTokenJson = GetObjFromJson(jsonObject, "HapTokenInfos");
    if (hapTokenJson != nullptr) {
        BaseRemoteCommand::FromHapTokenInfoJson(hapTokenJson, updateTokenInfo_);
    }

    rawDeviceId_ = rawDeviceId;
}

std::string UpdateRemoteHapTokenCommand::ToJsonPayload()
{
    CJsonUnique j = BaseRemoteCommand::ToRemoteProtocolJson();
    CJsonUnique hapTokenInfos = BaseRemoteCommand::ToHapTokenInfosJson(updateTokenInfo_);
    AddObjToJson(j, "HapTokenInfos", hapTokenInfos);
    return PackJsonToString(j);
}

void UpdateRemoteHapTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    LOGD(ATM_DOMAIN, ATM_TAG, "End as: UpdateRemoteHapTokenCommand");
}

void UpdateRemoteHapTokenCommand::Execute()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: start as: UpdateRemoteHapTokenCommand");

    remoteProtocol_.responseDeviceId = ConstantCommon::GetLocalDeviceId();
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    if (!CheckDeviceIdValid(remoteProtocol_.srcDeviceId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to UpdateRemoteHapTokenCommand, deviceId(%{public}s) invalid.",
            ConstantCommon::EncryptDevId(remoteProtocol_.srcDeviceId).c_str());
        return;
    }
    int ret = AccessTokenKit::SetRemoteHapTokenInfo(rawDeviceId_, updateTokenInfo_);
    if (ret != RET_SUCCESS) {
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        remoteProtocol_.message = Constant::COMMAND_RESULT_FAILED;
    } else {
        remoteProtocol_.statusCode = Constant::SUCCESS;
        remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: end as: UpdateRemoteHapTokenCommand");
}

void UpdateRemoteHapTokenCommand::Finish()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    LOGI(ATM_DOMAIN, ATM_TAG, "Finish: end as: UpdateRemoteHapTokenCommand");
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

