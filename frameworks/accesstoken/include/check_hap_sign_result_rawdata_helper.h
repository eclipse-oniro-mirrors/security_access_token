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

#ifndef ACCESSTOKEN_CHECK_HAP_SIGN_RESULT_RAWDATA_HELPER_H
#define ACCESSTOKEN_CHECK_HAP_SIGN_RESULT_RAWDATA_HELPER_H

#include "check_hap_sign_result_rawdata.h"
#include "hap_token_info.h"
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {

class CheckHapSignResultRawdataHelper {
public:
    static bool WriteToRawData(
        int32_t realResult,
        int32_t sessionId,
        const std::vector<TrustedBundleInfo>& bundleInfos,
        CheckHapSignResultRawdata& rawData);
    
    static bool ReadFromRawData(
        const CheckHapSignResultRawdata& rawData,
        int32_t& realResult,
        int32_t& sessionId,
        std::vector<TrustedBundleInfo>& bundleInfos);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_CHECK_HAP_SIGN_RESULT_RAWDATA_HELPER_H