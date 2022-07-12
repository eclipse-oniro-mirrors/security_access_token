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
#include "accesstoken_log.h"
#include "constant_common.h"
#include "base_remote_command.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SyncRemoteHapTokenCommand"};
}

SyncRemoteHapTokenCommand::SyncRemoteHapTokenCommand(
    const std::string &srcDeviceId, const std::string &dstDeviceId, AccessTokenID id) : requestTokenId_(id)
{
    remoteProtocol_.commandName = COMMAND_NAME;
    remoteProtocol_.uniqueId = COMMAND_NAME;
    remoteProtocol_.srcDeviceId = srcDeviceId;
    remoteProtocol_.dstDeviceId = dstDeviceId;
    remoteProtocol_.responseVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    remoteProtocol_.requestVersion = Constant::DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION;
    hapTokenInfo_.baseInfo.apl = APL_NORMAL;
    hapTokenInfo_.baseInfo.appID = "";
    hapTokenInfo_.baseInfo.bundleName = "";
    hapTokenInfo_.baseInfo.deviceID = "";
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
    hapTokenInfo_.baseInfo.apl = APL_INVALID;
    hapTokenInfo_.baseInfo.appID = "";
    hapTokenInfo_.baseInfo.bundleName = "";
    hapTokenInfo_.baseInfo.deviceID = "";
    hapTokenInfo_.baseInfo.instIndex = 0;
    hapTokenInfo_.baseInfo.dlpType = 0;
    hapTokenInfo_.baseInfo.tokenAttr = 0;
    hapTokenInfo_.baseInfo.tokenID = 0;
    hapTokenInfo_.baseInfo.userID = 0;
    hapTokenInfo_.baseInfo.ver = DEFAULT_TOKEN_VERSION;

    nlohmann::json jsonObject = nlohmann::json::parse(json, nullptr, false);
    BaseRemoteCommand::FromRemoteProtocolJson(jsonObject);
    if (jsonObject.find("requestTokenId") != jsonObject.end() && jsonObject.at("requestTokenId").is_number()) {
        jsonObject.at("requestTokenId").get_to(requestTokenId_);
    }

    if (jsonObject.find("HapTokenInfo") != jsonObject.end()) {
        nlohmann::json hapTokenJson = jsonObject.at("HapTokenInfo").get<nlohmann::json>();
        BaseRemoteCommand::FromHapTokenInfoJson(hapTokenJson, hapTokenInfo_);
    }
}

std::string SyncRemoteHapTokenCommand::ToJsonPayload()
{
    nlohmann::json j = BaseRemoteCommand::ToRemoteProtocolJson();
    j["requestTokenId"] = requestTokenId_;
    j["HapTokenInfo"] = BaseRemoteCommand::ToHapTokenInfosJson(hapTokenInfo_);
    return j.dump();
}

void SyncRemoteHapTokenCommand::Prepare()
{
    remoteProtocol_.statusCode = Constant::SUCCESS;
    remoteProtocol_.message = Constant::COMMAND_RESULT_SUCCESS;
    ACCESSTOKEN_LOG_DEBUG(LABEL, " end as: SyncRemoteHapTokenCommand");
}

void SyncRemoteHapTokenCommand::Execute()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "execute: start as: SyncRemoteHapTokenCommand");
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

    ACCESSTOKEN_LOG_INFO(LABEL, "execute: end as: SyncRemoteHapTokenCommand");
}

void SyncRemoteHapTokenCommand::Finish()
{
    if (remoteProtocol_.statusCode != Constant::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Finish: end as: SyncRemoteHapTokenCommand get remote result error.");
        return;
    }
    AccessTokenKit::SetRemoteHapTokenInfo(remoteProtocol_.dstDeviceId, hapTokenInfo_);
    remoteProtocol_.statusCode = Constant::SUCCESS;
    ACCESSTOKEN_LOG_INFO(LABEL, "Finish: end as: SyncRemoteHapTokenCommand");
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
