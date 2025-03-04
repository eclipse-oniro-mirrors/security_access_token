/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H
#define ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "permission_data_brief.h"
#include "permission_def.h"
#include "permission_status.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapTokenInfoInner final {
public:
    HapTokenInfoInner();
    HapTokenInfoInner(AccessTokenID id, const HapInfoParams& info, const HapPolicy& policy);
    HapTokenInfoInner(AccessTokenID id, const HapTokenInfo &info,
        const std::vector<PermissionStatus>& permStateList);
    HapTokenInfoInner(AccessTokenID id, const HapTokenInfoForSync& info);
    virtual ~HapTokenInfoInner();

    void Update(const UpdateHapInfoParams& info, const std::vector<PermissionStatus>& permStateList,
        const HapPolicy& hapPolicy);
    void TranslateToHapTokenInfo(HapTokenInfo& infoParcel) const;
    void StoreHapInfo(std::vector<GenericValues>& valueList, const std::string& appId, ATokenAplEnum apl) const;
    void StorePermissionPolicy(std::vector<GenericValues>& permStateValues);
    int RestoreHapTokenInfo(AccessTokenID tokenId, const GenericValues& tokenValue,
        const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues> extendedPermRes);

    uint32_t GetReqPermissionSize();
    HapTokenInfo GetHapInfoBasic() const;
    int GetUserID() const;
    int GetDlpType() const;
    std::string GetBundleName() const;
    int GetInstIndex() const;
    AccessTokenID GetTokenID() const;
    void SetTokenBaseInfo(const HapTokenInfo& baseInfo);
    void ToString(std::string& info);
    bool IsRemote() const;
    void SetRemote(bool isRemote);
    bool IsPermDialogForbidden() const;
    void SetPermDialogForbidden(bool isForbidden);

    int32_t UpdatePermissionStatus(
        const std::string& permissionName, bool isGranted, uint32_t flag, bool& statusChanged);
    int32_t GetPermissionStateList(std::vector<PermissionStatus>& permList);
    int32_t ResetUserGrantPermissionStatus(void);
    void UpdateRemoteHapTokenInfo(AccessTokenID mapID,
        const HapTokenInfo& baseInfo, std::vector<PermissionStatus>& permStateList);

    static void RefreshPermStateToKernel(const std::vector<std::string>& constrainedList,
        bool hapUserIsActive, AccessTokenID tokenId, std::map<std::string, bool>& refreshedPermList);
    static int32_t VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permissionName);
    static PermUsedTypeEnum GetPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName);
    static int32_t QueryPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    static void GetPermStatusListByTokenId(AccessTokenID tokenID,
        const std::vector<uint32_t> constrainedList, std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
    static void GetGrantedPermByTokenId(AccessTokenID tokenID,
        const std::vector<std::string>& constrainedList, std::vector<std::string>& permissionList);
    static void ClearAllSecCompGrantedPerm();
    static bool IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName);

    uint64_t permUpdateTimestamp_;
private:
    int32_t GetApiVersion(int32_t apiVersion);
    void StoreHapBasicInfo(std::vector<GenericValues>& valueList) const;
    void TranslationIntoGenericValues(GenericValues& outGenericValues) const;
    int RestoreHapTokenBasicInfo(const GenericValues& inGenericValues);
    bool UpdateStatesToDB(AccessTokenID tokenID, std::vector<PermissionStatus>& stateChangeList);
    void PermToString(const std::vector<PermissionDef>& permList,
        const std::vector<PermissionStatus>& permStateList, std::string& info);
    void PermStateFullToString(const PermissionStatus& state, std::string& info);

    HapTokenInfo tokenInfoBasic_;

    // true means sync from remote.
    bool isRemote_;
    /** permission dialog is forbidden */
    bool isPermDialogForbidden_ = false;

    OHOS::Utils::RWLock policySetLock_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H
