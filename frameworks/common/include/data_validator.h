/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef DATA_VALIDATOR_H
#define DATA_VALIDATOR_H

#include <map>
#include <string>
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class DataValidator final {
public:
    static bool IsBundleNameValid(const std::string& bundleName);

    static bool IsPermissionNameValid(const std::string& permissionName);

    static bool IsUserIdValid(const int userId);

    static bool IsToggleStatusValid(const uint32_t status);

    static bool IsAppIDDescValid(const std::string& appIDDesc);

    static bool IsDomainValid(const std::string& domain);

    static bool IsAplNumValid(const int apl);

    static bool IsAvailableTypeValid(const int availableType);

    static bool IsProcessNameValid(const std::string& processName);

    static bool IsDeviceIdValid(const std::string& deviceId);

    static bool IsLabelValid(const std::string& label);

    static bool IsDescValid(const std::string& desc);
    static bool IsPermissionFlagValid(uint32_t flag);
    static bool IsPermissionFlagValidForAdmin(uint32_t flag);
    static bool IsPermissionStatusValid(int32_t status);
    static bool IsDcapValid(const std::string& dcap);
    static bool IsTokenIDValid(AccessTokenID id);
    static bool IsDlpTypeValid(int dlpType);
    static bool IsPermissionUsedFlagValid(uint32_t flag);
    static bool IsPermissionUsedTypeValid(uint32_t type);
    static bool IsPolicyTypeValid(uint32_t type);
    static bool IsCallerTypeValid(uint32_t type);
    static bool IsNativeCaller(AccessTokenID id);
    static bool IsHapCaller(AccessTokenID id);
    static bool IsAclExtendedMapSizeValid(const std::map<std::string, std::string>& aclExtendedMap);
    static bool IsAclExtendedMapContentValid(const std::string& permissionName, const std::string& value);
    static bool IsPermissionListSizeValid(const std::vector<std::string>& permissionList);

private:
    const static int MAX_LENGTH = 256;
    const static int MAX_APPIDDESC_LENGTH = 10240;
    const static int MAX_DCAP_LENGTH = 1024;
    const static int32_t MAX_EXTENDED_MAP_SIZE = 512;
    const static int32_t MAX_VALUE_LENGTH = 1024;
    const static int32_t MAX_PERMISSION_LIST_SIZE = 1024;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // DATA_VALIDATOR_H
