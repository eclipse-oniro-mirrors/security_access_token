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

/**
 * @addtogroup AccessToken
 * @{
 *
 * @brief Provides permission management.
 *
 * Provides tokenID-based application permission verification mechanism.
 * When an application accesses sensitive data or APIs, this module can check
 * whether the application has the corresponding permission. Allows applications
 * to query their access token information or APL levcels based on token IDs.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file accesstoken_kit.h
 *
 * @brief Declares access token interfaces.
 *
 * @since 7.0
 * @version 7.0
 */

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H

#include <string>
#include <vector>

#include "access_token.h"
#include "atm_tools_param_info.h"
#include "hap_token_info.h"
#include "native_token_info.h"
#include "permission_def.h"
#include "permission_list_state.h"
#include "permission_grant_info.h"
#include "permission_state_change_info.h"
#include "permission_state_full.h"
#include "perm_state_change_callback_customize.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares AccessTokenKit class
 */
class AccessTokenKit {
public:
    /**
     * @brief Get permission used type by tokenID.
     * @param tokenID token id
     * @param permissionName permission to be checked
     * @return enum PermUsedTypeEnum, see access_token.h
     */
    static PermUsedTypeEnum GetUserGrantedPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName);
    /**
     * @brief Create a unique hap token by input values.
     * @param info struct HapInfoParams quote, see hap_token_info.h
     * @param policy struct HapPolicyParams quote, see hap_token_info.h
     * @return union AccessTokenIDEx, see access_token.h
     */
    static AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy);
    /**
     * @brief Create a unique hap token by input values and init the permission state.
     * @param info struct HapInfoParams quote, see hap_token_info.h
     * @param policy struct HapPolicyParams quote, see hap_token_info.h
     * @return union AccessTokenIDEx, see access_token.h
     */
    static int32_t InitHapToken(const HapInfoParams& info, HapPolicyParams& policy, AccessTokenIDEx& fullTokenId);
    /**
     * @brief Create a unique mapping token binding remote tokenID and DeviceID.
     * @param remoteDeviceID remote device deviceID
     * @param remoteTokenID remote device tokenID
     * @return local tokenID which mapped by local token
     */
    static AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    /**
     * @brief Update hap token info.
     * @param tokenIdEx union AccessTokenIDEx quote, see access_token.h
     * @param isSystemApp is system app or not
     * @param appIDDesc app id description quote
     * @param apiVersion app api version
     * @param policy struct HapPolicyParams quote, see hap_token_info.h
     * @return error code, see access_token_error.h
     */
    static int32_t UpdateHapToken(
        AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info, const HapPolicyParams& policy);
    /**
     * @brief Delete token info.
     * @param tokenID token id
     * @return error code, see access_token_error.h
     */
    static int DeleteToken(AccessTokenID tokenID);
    /**
     * @brief Get token type by ATM service.
     * @param tokenID token id
     * @return token type enum, see access_token.h
     */
    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    /**
     * @brief Get token type from flag in tokenId, which doesn't depend on ATM service.
     * @param tokenID token id
     * @return token type enum, see access_token.h
     */
    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID);
    /**
     * @brief Get token type by ATM service with uint_64 parameters.
     * @param tokenID token id
     * @return token type enum, see access_token.h
     */
    static ATokenTypeEnum GetTokenType(FullTokenID tokenID);
    /**
     * @brief Get token type from flag in tokenId, which doesn't depend
     *        on ATM service, with uint_64 parameters.
     * @param tokenID token id
     * @return token type enum, see access_token.h
     */
    static ATokenTypeEnum GetTokenTypeFlag(FullTokenID tokenID);
    /**
     * @brief Check native token dcap by token id.
     * @param tokenID token id
     * @param dcap dcap to be checked
     * @return error code, see access_token_error.h
     */
    static int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap);
    /**
     * @brief Query hap tokenID by input prarms.
     * @param userID user id
     * @param bundleName bundle name
     * @param instIndex inst index
     * @return token id if exsit or 0 if not exsit
     */
    static AccessTokenID GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex);
    /**
     * @brief Query hap token attribute by input prarms.
     * @param userID user id
     * @param bundleName bundle name
     * @param instIndex inst index
     * @return union AccessTokenIDEx, see access_token.h
     */
    static AccessTokenIDEx GetHapTokenIDEx(int32_t userID, const std::string& bundleName, int32_t instIndex);
    /**
     * @brief Get hap token info by token id.
     * @param tokenID token id
     * @param hapTokenInfoRes HapTokenInfo quote, as query result
     * @return error code, see access_token_error.h
     */
    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes);
    /**
     * @brief Get native token info by token id.
     * @param tokenID token id
     * @param nativeTokenInfoRes NativeTokenInfo quote, as query result
     * @return error code, see access_token_error.h
     */
    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes);
    /**
     * @brief Check if the input tokenID has been granted the input permission.
     * @param tokenID token id
     * @param permissionName permission to be checked
     * @return enum PermissionState, see access_token.h
     */
    static int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    /**
     * @brief Check if the input tokenID has been granted the input permission.
     * @param callerTokenID the tokenID of caller native process or hap process
     * @param firstTokenID the tokenID of first caller native process or hap process
     * @param permissionName permission to be checked
     * @return enum PermissionState, see access_token.h
     */
    static int VerifyAccessToken(
        AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName);
        /**
     * @brief Check if the input tokenID has been granted the input permission.
     * @param tokenID token id
     * @param permissionName permission to be checked
     * @param crossIpc whether to cross ipc
     * @return enum PermissionState, see access_token.h
     */
    static int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName, bool crossIpc);
    /**
     * @brief Check if the input tokenID has been granted the input permission.
     * @param callerTokenID the tokenID of caller native process or hap process
     * @param firstTokenID the tokenID of first caller native process or hap process
     * @param permissionName permission to be checked
     * @param crossIpc whether to cross ipc
     * @return enum PermissionState, see access_token.h
     */
    static int VerifyAccessToken(AccessTokenID callerTokenID,
        AccessTokenID firstTokenID, const std::string& permissionName, bool crossIpc);

    /**
     * @brief Get permission definition by permission name.
     * @param permissionName permission name quote
     * @param permissionDefResult PermissionDef quote, as query result
     * @return error code, see access_token_error.h
     */
    static int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    /**
     * @brief Get all permission definitions by token id.
     * @param tokenID token id
     * @param permList PermissionDef list quote, as query result
     * @return error code, see access_token_error.h
     */
    static int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    /**
     * @brief Get all requested permission full state by token id and grant mode.
     * @param tokenID token id
     * @param reqPermList PermissionStateFull list quote, as query result
     * @param isSystemGrant grant mode
     * @return error code, see access_token_error.h
     */
    static int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    /**
     * @brief Get permission grant flag
     * @param tokenID token id
     * @param permissionName permission name quote
     * @param flag the permission grant flag, as query result
     * @return error code, see access_token_error.h
     */
    static int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    /**
     * @brief Set permission request toggle status
     * @param permissionName permission name quote
     * @param status the permission request toggle status to set
     * @param userID the userID
     * @return error code, see access_token_error.h
     */
    static int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status, int32_t userID);
    /**
     * @brief Get permission request toggle status
     * @param permissionName permission name quote
     * @param status the permission request toggle status to get
     * @param userID the userID
     * @return error code, see access_token_error.h
     */
    static int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
        int32_t userID);
    /**
     * @brief Get requsted permission grant result
     * @param permList PermissionListState list quote, as input and query result
     * @return enum PermissionOper, see access_token.h
     */
    static PermissionOper GetSelfPermissionsState(std::vector<PermissionListState>& permList,
        PermissionGrantInfo& info);
    /**
     * @brief Get requsted permissions status
     * @param permList PermissionListState list quote, as input and query result
     * @return error code, see access_token_error.h
     */
    static int32_t GetPermissionsStatus(AccessTokenID tokenID, std::vector<PermissionListState>& permList);
    /**
     * @brief Grant input permission to input tokenID with input flag.
     * @param tokenID token id
     * @param permissionName permission name quote
     * @param flag enum PermissionFlag, see access_token.h
     * @return error code, see access_token_error.h
     */
    static int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    /**
     * @brief Revoke input permission to input tokenID with input flag.
     * @param tokenID token id
     * @param permissionName permission name quote
     * @param flag enum PermissionFlag, see access_token.h
     * @return error code, see access_token_error.h
     */
    static int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    /**
     * @brief Clear all user granted permissions state in input tokenID.
     * @param tokenID token id
     * @return error code, see access_token_error.h
     */
    static int ClearUserGrantedPermissionState(AccessTokenID tokenID);
    /**
     * @brief Register permission state change callback.
     * @param callback smart point of class PermStateChangeCallbackCustomize quote
     * @return error code, see access_token_error.h
     */
    static int32_t RegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& callback);
    /**
     * @brief Unregister permission state change callback.
     * @param callback smart point of class PermStateChangeCallbackCustomize quote
     * @return error code, see access_token_error.h
     */
    static int32_t UnRegisterPermStateChangeCallback(const std::shared_ptr<PermStateChangeCallbackCustomize>& callback);
    /**
     * @brief Get current version.
     * @param version access token version.
     * @return error code, see access_token_error.h
     */
    static int32_t GetVersion(uint32_t& version);
    /**
     * @brief Get hap dlp flag by input tokenID.
     * @param tokenID token id
     * @return dlp flag in tokenID bitmap, or default -1
     */
    static int32_t GetHapDlpFlag(AccessTokenID tokenID);
    /**
     * @brief Reload native token info.
     * @return error code, see access_token_error.h
     */
    static int32_t ReloadNativeTokenInfo();
    /**
     * @brief Get tokenID by native process name.
     * @param processName native process name
     * @return token id of native process
     */
    static AccessTokenID GetNativeTokenId(const std::string& processName);

    /**
     * @brief Set permission dialog capability
     * @param hapBaseInfo base infomation of hap
     * @param enable status of enable dialog
     * @return error code, see access_token_error.h
     */
    static int32_t SetPermDialogCap(const HapBaseInfo& hapBaseInfo, bool enable);

#ifdef TOKEN_SYNC_ENABLE
    /**
     * @brief Get remote hap token info by remote token id.
     * @param tokenID remote token id
     * @param hapSync HapTokenInfoForSync quote, as query result
     * @return error code, see access_token_error.h
     */
    static int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    /**
     * @brief Get all native token infos.
     * @param nativeTokenInfosRes NativeTokenInfoForSync list quote
     *        as input and query result
     * @return error code, see access_token_error.h
     */
    static int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes);
    /**
     * @brief Set remote hap token info with remote deviceID.
     * @param deviceID remote deviceID
     * @param hapSync hap token info to set
     * @return error code, see access_token_error.h
     */
    static int SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    /**
     * @brief Set remote native token info list with remote deviceID.
     * @param deviceID remote deviceID
     * @param nativeTokenInfoList native token info list to set
     * @return error code, see access_token_error.h
     */
    static int SetRemoteNativeTokenInfo(const std::string& deviceID,
        const std::vector<NativeTokenInfoForSync>& nativeTokenInfoList);
    /**
     * @brief Delete remote token by remote deviceID and remote tokenID.
     * @param deviceID remote deviceID
     * @param tokenID remote tokenID
     * @return error code, see access_token_error.h
     */
    static int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    /**
     * @brief Get local mapping native tokenID by remote deviceID
     *        and remote tokenID.
     * @param deviceID remote deviceID
     * @param tokenID remote tokenID
     * @return token id of mapping native tokenID
     */
    static AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    /**
     * @brief Delete remote tokens by remote deviceID.
     * @param deviceID remote deviceID
     * @return error code, see access_token_error.h
     */
    static int DeleteRemoteDeviceTokens(const std::string& deviceID);
    /**
     * @brief Regist a token sync service callback
     * @param syncCallback token sync class
     * @return error code, see access_token_error.h
     */
    static int32_t RegisterTokenSyncCallback(const std::shared_ptr<TokenSyncKitInterface>& syncCallback);
    /**
     * @brief UnRegist a token sync service callback
     * @param syncCallback token sync class
     * @return error code, see access_token_error.h
     */
    static int32_t UnRegisterTokenSyncCallback();
#endif
    /**
     * @brief Dump all token infos in the cache.
     * @param tokenID token id, if tokenID is valid, only dump this token info
     * @param dumpInfo all token info
     */
    static void DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo);
    /**
     * @brief Dump all permission definition infos.
     * @param dumpInfo all permission definition info
     * @return error code, see access_token_error.h
     */
    static int32_t DumpPermDefInfo(std::string& dumpInfo);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
