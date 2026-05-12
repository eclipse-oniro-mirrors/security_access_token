/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_HAP_DATA_STRUCTURE_H
#define ACCESS_TOKEN_HAP_DATA_STRUCTURE_H

#include <cstdint>
#include <string>
#include <vector>

#include "access_token.h"
#ifdef SUPPORT_JSAPI
#include "provision/provision_info.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {

struct BundleParam final {
    std::string bundleName;
    std::string appId;
    uint64_t appIdentifier = 0;
    int32_t apiVersion = 0;
#ifdef SUPPORT_JSAPI
    Verify::AppDistType distributionType = Verify::AppDistType::NONE_TYPE;
#endif
    bool isSystem = false;
    bool isAtomicService = false;
    bool isDebug = false;
};

class BundleNoCachedInfo final {
public:
    ATokenAplEnum apl = APL_INVALID;
#ifdef SUPPORT_JSAPI
    Verify::AppDistType distributionType = Verify::AppDistType::NONE_TYPE;
#endif
    uint32_t idType = 0;
    uint64_t ownerid = 0;
};

class BundleInfoInner final {
public:
    std::vector<uint16_t> permCodeList;
    std::vector<AccessTokenID> tokenIds;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_HAP_DATA_STRUCTURE_H
