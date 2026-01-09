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
#ifndef BASE_REMOTE_COMMON_H
#define BASE_REMOTE_COMMON_H

#include <vector>

#include "cjson_utils.h"
#include "constant.h"
#include "hap_token_info.h"
#include "native_token_info_base.h"
#include "permission_status.h"
#include "remote_protocol.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * The base class for command. You can treat this as remote command header.
 */
class BaseRemoteCommand {
public:
    BaseRemoteCommand() = default;
    virtual ~BaseRemoteCommand() = default;

    /* Prepare() is called in requestor */
    virtual void Prepare() = 0;

    /* Execute() is called in responser */
    virtual void Execute() = 0;

    /* Finish() is called in requestor, after get response, but the command object is not same with the request */
    virtual void Finish() = 0;

    virtual std::string ToJsonPayload() = 0;
    CJsonUnique ToRemoteProtocolJson();
    void FromRemoteProtocolJson(const CJson* jsonObject);

    void ToPermStateJson(CJson* permStateJson, const PermissionStatus& state);
    bool FromPermStateJson(const CJson* permStateJson, PermissionStatus& permission);
    void FromPermStateListJson(const CJson* hapTokenJson,
        std::vector<PermissionStatus>& permStateList);

    void FromHapTokenBasicInfoJson(const CJson* hapTokenJson,
        HapTokenInfo& hapTokenBasicInfo);

    CJsonUnique ToHapTokenInfosJson(const HapTokenInfoForSync &tokenInfo);
    void FromHapTokenInfoJson(const CJson* hapTokenJson, HapTokenInfoForSync& hapTokenInfo);
    CJsonUnique ToNativeTokenInfoJson(const NativeTokenInfoBase& tokenInfo);
    void FromNativeTokenInfoJson(const CJson* nativeTokenJson, NativeTokenInfoBase& nativeTokenInfo);
    bool CheckDeviceIdValid(const std::string& deviceId);
    RemoteProtocol remoteProtocol_;
    std::string rawDeviceId_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // BASE_REMOTE_COMMON_H
