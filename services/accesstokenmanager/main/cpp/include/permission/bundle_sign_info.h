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

#ifndef ACCESS_TOKEN_BUNDLE_SIGN_INFO_H
#define ACCESS_TOKEN_BUNDLE_SIGN_INFO_H

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "access_token_error.h"
#include "generic_values.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct BundleSignInfo final {
    std::string bundleName;
    bool isPreInstalled = false;
    std::vector<std::string> moduleNameList;
    std::vector<std::string> pathList;
    std::vector<uint32_t> bundleType;
    std::vector<std::vector<uint8_t>> persistDataList;

    int32_t ToGenericValues(std::vector<GenericValues>& valueList) const
    {
        size_t itemSize = moduleNameList.size();
        if ((pathList.size() != itemSize) || (bundleType.size() != itemSize) ||
            (persistDataList.size() != itemSize)) {
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        for (size_t i = 0; i < itemSize; ++i) {
            GenericValues value;
            value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
            value.Put(TokenFiledConst::FIELD_MODULE_NAME, moduleNameList[i]);
            value.Put(TokenFiledConst::FIELD_PATH, pathList[i]);
            value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistDataList[i]);
            value.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(isPreInstalled));
            value.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(bundleType[i]));
            valueList.emplace_back(value);
        }
        return RET_SUCCESS;
    }
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_BUNDLE_SIGN_INFO_H
