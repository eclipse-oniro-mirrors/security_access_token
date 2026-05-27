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

#ifndef ACCESS_TOKEN_TABLE_ITEM_H
#define ACCESS_TOKEN_TABLE_ITEM_H

#include <string>
#include <vector>

#include "access_token.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "nocopyable.h"
#include "permission_status.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class TableItem {
public:
    virtual ~TableItem() = default;
};

class ModuleInfoItem final : public TableItem {
public:
    std::string moduleName;
    std::string path;
    int32_t bundleType = 0;
    std::vector<uint8_t> persistData;

    void BuildAddValue(std::vector<GenericValues>& addValues) const;
};

struct BundleInfoItems final : public TableItem {
    std::string bundleName;
    bool isPreInstalled = false;
    std::vector<ModuleInfoItem> moduleInfoItems;

    inline static constexpr AtmDataType type_ = ACCESSTOKEN_HAP_PACKAGE_INFO;

    void BuildAddValue(std::vector<GenericValues>& addValues) const;
    void BuildDeleteValues(GenericValues& deleteValue) const;
    void BuildUpdateValues(GenericValues& deleteValue, std::vector<GenericValues>& addValues) const;
    void BuildFindValues(GenericValues& findValue) const;

    static void LoadFromDB(const std::vector<GenericValues>& values, std::vector<BundleInfoItems>& items);
    static void GenerateAddList(const std::vector<GenericValues>& values, std::vector<AddInfo>& addInfoVec);
    static void GenerateDelList(const std::vector<GenericValues>& values, DelInfo& delInfo);
};

struct HapTokenInfoItem final : public TableItem {
    AccessTokenID tokenId = INVALID_TOKENID;
    uint32_t userId = 0;
    std::string bundleName;
    uint32_t instIndex = 0;
    HapDlpType dlpType = DLP_COMMON;
    std::string appId = "";
    std::string deviceId = "0";
    ATokenAplEnum apl = APL_INVALID;
    uint32_t version = 0;
    uint32_t tokenAttr = 0;
    int32_t apiVersion = 0;
    bool permDialogCapState = false;
    int32_t uid = 0;
    bool migrated = false;
    ReservedType reserved = ReservedType::NONE;

    inline static constexpr AtmDataType type_ = ACCESSTOKEN_HAP_INFO;

    void BuildAddValue(std::vector<GenericValues>& addValues) const;
    void BuildDeleteValues(GenericValues& deleteValue) const;
    void BuildUpdateValues(GenericValues& deleteValue, std::vector<GenericValues>& addValues) const;
    void BuildFindValues(GenericValues& findValue) const;

    static void LoadFromDB(const std::vector<GenericValues>& values, std::vector<HapTokenInfoItem>& items);
    static void GenerateAddList(const std::vector<GenericValues>& values, std::vector<AddInfo>& addInfoVec);
    static void GenerateDelList(const std::vector<GenericValues>& values, DelInfo& delInfo);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_TABLE_ITEM_H
