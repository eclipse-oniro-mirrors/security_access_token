/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_CONFIG_POLICY_LOADER_H
#define ACCESSTOKEN_CONFIG_POLICY_LOADER_H

#include <string>
#include <vector>
#include "hap_token_info.h"
#include "permission_def.h"
#include "native_token_info_base.h"
#include "permission_dlp_mode.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const static std::string CONFIG_PARSE_LIBPATH = "libaccesstoken_json_parse.z.so";
struct AccessTokenServiceConfig final {
    std::string grantBundleName;
    std::string grantAbilityName;
    std::string grantServiceAbilityName;
    std::string permStateAbilityName;
    std::string globalSwitchAbilityName;
    int32_t cancelTime = 0;
    std::string applicationSettingAbilityName;
    std::string openSettingAbilityName;
    std::vector<std::string> enterpriseNormalPermissiveBundles;
};

struct PrivacyServiceConfig final {
    int32_t sizeMaxImum;
    int32_t agingTime;
    std::string globalDialogBundleName;
    std::string globalDialogAbilityName;
};

struct TokenSyncServiceConfig final {
    int32_t sendRequestRepeatTimes;
};

struct AccessTokenConfigValue {
    AccessTokenServiceConfig atConfig;
    PrivacyServiceConfig pConfig;
    TokenSyncServiceConfig tsConfig;
};

enum ServiceType {
    ACCESSTOKEN_SERVICE = 0,
    PRIVACY_SERVICE,
    TOKENSYNC_SERVICE,
};

struct PermissionDefParseRet {
    PermissionDef permDef;
    bool isSuccessful = false;
};

class ConfigPolicyLoaderInterface {
public:
    ConfigPolicyLoaderInterface() {}
    virtual ~ConfigPolicyLoaderInterface() {}
    virtual bool GetConfigValue(const ServiceType& type, AccessTokenConfigValue& config);
    virtual int32_t GetAllNativeTokenInfo(std::vector<NativeTokenInfoBase>& tokenInfos);
    virtual int32_t GetDlpPermissions(std::vector<PermissionDlpMode>& dlpPerms);
    virtual std::string DumpNativeTokenInfo(const NativeTokenInfoBase& native);
    virtual std::string DumpHapTokenInfo(const HapTokenInfo& hapInfo, bool isRemote, bool isPermDialogForbidden,
        const std::vector<PermissionStatus>& permStateList);
};

class ConfigPolicLoader final: public ConfigPolicyLoaderInterface {
    bool GetConfigValue(const ServiceType& type, AccessTokenConfigValue& config);
    int32_t GetAllNativeTokenInfo(std::vector<NativeTokenInfoBase>& tokenInfos);
    int32_t GetDlpPermissions(std::vector<PermissionDlpMode>& dlpPerms);
    std::string DumpNativeTokenInfo(const NativeTokenInfoBase& native);
    std::string DumpHapTokenInfo(const HapTokenInfo& hapInfo, bool isRemote, bool isPermDialogForbidden,
        const std::vector<PermissionStatus>& permStateList);
private:
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    void GetConfigFilePathList(std::vector<std::string>& pathList);
    bool GetConfigValueFromFile(const ServiceType& type, const std::string& fileContent,
        AccessTokenConfigValue& config);
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
    bool ParserNativeRawData(const std::string& nativeRawData, std::vector<NativeTokenInfoBase>& tokenInfos);
    bool ParserDlpPermsRawData(const std::string& dlpPermsRawData, std::vector<PermissionDlpMode>& dlpPerms);
    int32_t ReadCfgFile(const std::string& file, std::string& rawData);
    bool IsDirExsit(const std::string& file);
};

#ifdef __cplusplus
extern "C" {
#endif
    void* Create();
    void Destroy(void* loaderPtr);
#ifdef __cplusplus
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_CONFIG_POLICY_LOADER_H
