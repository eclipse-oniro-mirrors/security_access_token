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

#ifndef ACCESSTOKEN_BUNDLE_INFOS_RAWDATA_HELPER_H
#define ACCESSTOKEN_BUNDLE_INFOS_RAWDATA_HELPER_H

#include "bundle_infos_rawdata.h"
#include "hap_token_info.h"
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {

class BundleInfosRawdataHelper {
public:
    static bool WriteToRawData(const std::vector<TrustedBundleInfo>& bundleInfos, BundleInfosRawdata& rawData);
    static bool ReadFromRawData(const BundleInfosRawdata& rawData, std::vector<TrustedBundleInfo>& bundleInfos);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_BUNDLE_INFOS_RAWDATA_HELPER_H