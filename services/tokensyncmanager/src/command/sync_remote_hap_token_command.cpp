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

#include "sync_remote_hap_token_command.h"

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "constant_common.h"
#include "base_remote_command.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

SyncRemoteHapTokenCommand::SyncRemoteHapTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, AccessTokenID id) : requestTokenId_(id)
{
    remoteProtocol_.commandName = COMMAND_NAME;
    remoteProtocol_.uniqueId = COMMAND_NAME;
    remoteProtocol_.srcDeviceId = srcDeviceId;
    remoteProtocol_.dstDeviceId = dstDeviceId;
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    remoteProtocol_.requestVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    hapTokenInfo_.baseInfo.bundleName = "";
    hapTokenInfo_.baseInfo.instIndex = 0;
    hapTokenInfo_.baseInfo.dlpType = 0;
    hapTokenInfo_.baseInfo.tokenAttr = 0;
    hapTokenInfo_.baseInfo.tokenID = 0;
    hapTokenInfo_.baseInfo.userID = 0;
    hapTokenInfo_.baseInfo.ver = DEFAULT_TOKEN_VERSION;
}

SyncRemoteHapTokenCommand::SyncRemoteHapTokenCommand(const std::string &json)
{
    requestTokenId_ = 0;
    hapTokenInfo_.baseInfo.bundleName = "";
    hapTokenInfo_.baseInfo.instIndex = 0;
    hapTokenInfo_.baseInfo.dlpType = 0;
    hapTokenInfo_.baseInfo.tokenAttr = 0;
    hapTokenInfo_.baseInfo.tokenID = 0;
    hapTokenInfo_.baseInfo.userID = 0;
    hapTokenInfo_.baseInfo.ver = DEFAULT_TOKEN_VERSION;

    CJsonUnique jsonObject = CreateJsonFromString(json);
    if (jsonObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "JsonObject is invalid.");
        return;
    }
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject.get());
    GetUnsignedIntFromJson(jsonObject, "requestTokenId", requestTokenId_);

    CJson *hapTokenJson = GetObjFromJson(jsonObject, "HapTokenInfo");
    if (hapTokenJson != nullptr) {
        BaseRemoteCommand::FromHapTokenInfoJson(hapTokenJson, hapTokenInfo_);
    }
}

std::string SyncRemoteHapTokenCommand::ToJsonPayload()
{
    CJsonUnique j = BaseRemoteCommand::ToRemoteProtocolJson();
    AddUnsignedIntToJson(j, "requestTokenId", requestTokenId_);
    CJsonUnique HapTokenInfo = BaseRemoteCommand::ToHapTokenInfosJson(hapTokenInfo_);
    AddObjToJson(j, "HapTokenInfo", HapTokenInfo);
    return PackJsonToString(j);
}

void SyncRemoteHapTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    LOGD(ATM_DOMAIN, ATM_TAG, " end as: SyncRemoteHapTokenCommand");
}

void SyncRemoteHapTokenCommand::Execute()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: start as: SyncRemoteHapTokenCommand");
    remoteProtocol_.responseDeviceId = ConstantCommon::GetLocalDeviceId();
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;

    int ret = AccessTokenKit::GetHapTokenInfoFromRemote(requestTokenId_, hapTokenInfo_);
    if (ret != RET_SUCCESS) {
        remoteProtocol_.statusCode = Constant::FAILURE_BUT_CAN_RETRY;
        remoteProtocol_.message = Constant::COMMAND_RESULT_FAILED;
    } else {
        remoteProtocol_.statusCode = Constant::SUCCESS;
        remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Execute: end as: SyncRemoteHapTokenCommand");
}

void SyncRemoteHapTokenCommand::Finish()
{
    if (remoteProtocol_.statusCode != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Finish: end as: SyncRemoteHapTokenCommand get remote result error.");
        return;
    }
    AccessTokenKit::SetRemoteHapTokenInfo(remoteProtocol_.dstDeviceId, hapTokenInfo_);
    remoteProtocol_.statusCode = Constant::SUCCESS;
    LOGI(ATM_DOMAIN, ATM_TAG, "Finish: end as: SyncRemoteHapTokenCommand");
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
