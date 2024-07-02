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

namespace OHOS {
namespace Security {
namespace AccessToken {
const static std::string CONFIG_POLICY_LIBPATH = "libaccesstoken_config_policy.z.so";
struct AccessTokenServiceConfig final {
    std::string grantBundleName;
    std::string grantAbilityName;
    std::string permStateAbilityName;
    std::string globalSwitchAbilityName;
    int32_t cancleTime;
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

class ConfigPolicyLoaderInterface {
public:
    ConfigPolicyLoaderInterface() {}
    virtual ~ConfigPolicyLoaderInterface() {}
    virtual bool GetConfigValue(const ServiceType& type, AccessTokenConfigValue& config);
};

class ConfigPolicLoader final: public ConfigPolicyLoaderInterface {
    bool GetConfigValue(const ServiceType& type, AccessTokenConfigValue& config);
private:
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    void GetConfigFilePathList(std::vector<std::string>& pathList);
    bool IsConfigValueValid(const ServiceType& type, const AccessTokenConfigValue& config);
    bool GetConfigValueFromFile(const ServiceType& type, const std::string& fileContent,
        AccessTokenConfigValue& config);
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE
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