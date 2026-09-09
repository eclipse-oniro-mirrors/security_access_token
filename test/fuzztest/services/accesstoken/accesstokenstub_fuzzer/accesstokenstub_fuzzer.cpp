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

#include "accesstokenstub_fuzzer.h"

#include <climits>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unistd.h>
#include "access_token_db_operator.h"
#include "accesstoken_callback_stubs.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "iaccess_token_manager.h"
#include "mock_permission.h"
#include "permission_data_brief.h"
#include "token_field_const.h"
#include "token_setproc.h"
#include "token_sync_kit_interface.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static const uint64_t FUZZ_SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);
static AccessTokenID g_selfTokenId = 0;
static uint64_t g_syncTokenId = 0;
static AccessTokenID g_hdcdTokenID = 0;
static AccessTokenID g_manageUserPolicyTokenId = INVALID_TOKENID;
const static int32_t FLAG_SIZE = 16;
const int CONSTANTS_NUMBER_TWO = 2;
static const vector<PermissionFlag> FLAG_LIST = {
    PERMISSION_DEFAULT_FLAG,
    PERMISSION_USER_SET,
    PERMISSION_USER_FIXED,
    PERMISSION_SYSTEM_FIXED,
    PERMISSION_PRE_AUTHORIZED_CANCELABLE,
    PERMISSION_COMPONENT_SET,
    PERMISSION_FIXED_FOR_SECURITY_POLICY,
    PERMISSION_ALLOW_THIS_TIME
};
static const uint32_t FLAG_LIST_SIZE = 8;
static const std::string VALID_USER_POLICY_PERMISSION = "ohos.permission.INTERNET";
static constexpr int32_t VALID_USER_POLICY_USER_ID = 0;
static constexpr int32_t UNDEFINED_INFO_TOKEN_ID = 123; // 123: invalid token id, same as unit test
static constexpr int32_t ASYNC_DB_WAIT_SECONDS = 2; // 2: seconds to wait for UpdateDatabaseAsync
static const std::string MISMATCHED_PERM_DEF_VERSION = "fuzz_mismatched_perm_def_version";
static const std::string UNDEFINED_USER_GRANT_PERM = "ohos.permission.ACTIVITY_MOTION";
static const std::string UNDEFINED_SYSTEM_GRANT_PERM = "ohos.permission.REFRESH_USER_ACTION";
static bool g_isPermDefUpdateTriggered = false;

namespace OHOS {
class TokenSyncCallbackImpl : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackImpl() = default;
    virtual ~TokenSyncCallbackImpl() = default;

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override
    {
        return TokenSyncError::TOKEN_SYNC_OPENSOURCE_DEVICE;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override
    {
        return TokenSyncError::TOKEN_SYNC_SUCCESS;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override
    {
        return TokenSyncError::TOKEN_SYNC_SUCCESS;
    };
};

void RegisterTokenSyncCallback()
{
#ifdef TOKEN_SYNC_ENABLE
    (void)SetSelfTokenID(g_syncTokenId);
    sptr<TokenSyncCallbackImpl> callback = new (std::nothrow) TokenSyncCallbackImpl();
    if (callback == nullptr) {
        return;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteRemoteObject(callback->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_REGISTER_TOKEN_SYNC_CALLBACK);
    
    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
#endif // TOKEN_SYNC_ENABLE
}

void UnRegisterTokenSyncCallback()
{
#ifdef TOKEN_SYNC_ENABLE
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UN_REGISTER_TOKEN_SYNC_CALLBACK),
        datas, reply, option);
#endif // TOKEN_SYNC_ENABLE
}

void GetVersion()
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_VERSION), datas, reply, option);
}

void GetPermissionManagerInfo()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_PERMISSION_MANAGER_INFO), data, reply, option);
}

void InitHapInfoParams(const std::string& bundleName, FuzzedDataProvider& provider, HapInfoParams& param)
{
    param.userID = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX);
    param.bundleName = bundleName;
    param.instIndex = provider.ConsumeIntegral<int32_t>();
    param.dlpType = static_cast<int32_t>(
        provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(HapDlpType::BUTT_DLP_TYPE)));
    param.appIDDesc = provider.ConsumeRandomLengthString();
    param.apiVersion = provider.ConsumeIntegral<int32_t>();
    param.isSystemApp = provider.ConsumeBool();
    param.appDistributionType = provider.ConsumeRandomLengthString();
    param.isRestore = provider.ConsumeBool();
    param.tokenID = ConsumeTokenId(provider);
    param.isAtomicService = provider.ConsumeBool();
}

void InitValidHapInfoParams(HapInfoParams& param)
{
    param.userID = VALID_USER_POLICY_USER_ID;
    param.bundleName = "accesstokenstub.fuzzer";
    param.instIndex = 0;
    param.dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON);
    param.appIDDesc = "fuzzer";
    param.apiVersion = 8; // 8: api version
    param.isSystemApp = false;
    param.appDistributionType = "";
    param.isRestore = false;
    param.tokenID = 0;
    param.isAtomicService = false;
}

void InitValidHapPolicy(HapPolicy& policy)
{
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
}

AccessTokenID EnsureManageUserPolicyTestToken()
{
    if (g_manageUserPolicyTokenId != INVALID_TOKENID) {
        return g_manageUserPolicyTokenId;
    }

    HapInfoParcel hapInfoParcel;
    InitValidHapInfoParams(hapInfoParcel.hapInfoParameter);
    HapPolicyParcel hapPolicyParcel;
    InitValidHapPolicy(hapPolicyParcel.hapPolicy);

    uint64_t fullTokenIdValue = 0;
    int32_t ret = DelayedSingleton<AccessTokenManagerService>::GetInstance()->AllocHapToken(
        hapInfoParcel, hapPolicyParcel, fullTokenIdValue);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }

    AccessTokenIDEx fullTokenId = { .tokenIDEx = fullTokenIdValue };
    g_manageUserPolicyTokenId = fullTokenId.tokenIdExStruct.tokenID;
    return g_manageUserPolicyTokenId;
}

void InitHapPolicy(const std::string& permissionName, const std::string& bundleName, FuzzedDataProvider& provider,
    HapPolicy& policy)
{
    PermissionDef def = {
        .permissionName = permissionName,
        .bundleName = bundleName,
        .grantMode = static_cast<int32_t>(
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(GrantMode::SYSTEM_GRANT))),
        .availableLevel = static_cast<ATokenAplEnum>(
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT))),
        .provisionEnable = provider.ConsumeBool(),
        .distributedSceneEnable = provider.ConsumeBool(),
        .label = provider.ConsumeRandomLengthString(),
        .labelId = provider.ConsumeIntegral<int32_t>(),
        .description = provider.ConsumeRandomLengthString(),
        .descriptionId = provider.ConsumeIntegral<int32_t>(),
        .availableType = static_cast<ATokenAvailableTypeEnum>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(ATokenAvailableTypeEnum::AVAILABLE_TYPE_BUTT))),
        .isKernelEffect = provider.ConsumeBool(),
        .hasValue = provider.ConsumeBool(),
    };

    PermissionStatus state = {
        .permissionName = permissionName,
        .grantStatus = static_cast<int32_t>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionState::PERMISSION_GRANTED))),
        .grantFlag = 1 << (provider.ConsumeIntegral<uint32_t>() % FLAG_SIZE),
    };

    PreAuthorizationInfo info = {
        .permissionName = permissionName,
        .userCancelable = provider.ConsumeBool(),
    };

    policy.apl = static_cast<ATokenAplEnum>(
        provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT)));
    policy.domain = provider.ConsumeRandomLengthString();
    policy.permList = { def };
    policy.permStateList = { state };
    policy.aclRequestedList = {ConsumePermissionName(provider)};
    policy.preAuthorizationInfo = { info };
    policy.checkIgnore = static_cast<HapPolicyCheckIgnore>(provider.ConsumeIntegralInRange<uint32_t>(
        0, static_cast<uint32_t>(HapPolicyCheckIgnore::ACL_IGNORE_CHECK)));
    policy.aclExtendedMap = {std::make_pair<std::string, std::string>(provider.ConsumeRandomLengthString(),
        provider.ConsumeRandomLengthString())};
}

void InitHapPolicy(FuzzedDataProvider& provider, HapPolicy& policy)
{
    std::string permissionName = ConsumePermissionName(provider);
    PermissionDef def = {
        .permissionName = permissionName,
        .bundleName = ConsumeProcessName(provider),
        .grantMode = static_cast<int32_t>(
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(GrantMode::SYSTEM_GRANT))),
        .availableLevel = static_cast<ATokenAplEnum>(
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT))),
        .provisionEnable = provider.ConsumeBool(),
        .distributedSceneEnable = provider.ConsumeBool(),
        .label = provider.ConsumeRandomLengthString(),
        .labelId = provider.ConsumeIntegral<int32_t>(),
        .description = provider.ConsumeRandomLengthString(),
        .descriptionId = provider.ConsumeIntegral<int32_t>(),
        .availableType = static_cast<ATokenAvailableTypeEnum>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(ATokenAvailableTypeEnum::AVAILABLE_TYPE_BUTT))),
        .isKernelEffect = provider.ConsumeBool(),
        .hasValue = provider.ConsumeBool(),
    };

    PermissionStatus state = {
        .permissionName = permissionName,
        .grantStatus = static_cast<int32_t>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionState::PERMISSION_GRANTED))),
        .grantFlag = provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(PermissionFlag::PERMISSION_ALLOW_THIS_TIME)),
    };

    PreAuthorizationInfo info = {
        .permissionName = permissionName,
        .userCancelable = provider.ConsumeBool(),
    };

    policy.apl = static_cast<ATokenAplEnum>(
        provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT)));
    policy.domain = provider.ConsumeRandomLengthString();
    policy.permList = { def };
    policy.permStateList = { state };
    policy.aclRequestedList = {provider.ConsumeRandomLengthString()};
    policy.preAuthorizationInfo = { info };
    policy.checkIgnore = static_cast<HapPolicyCheckIgnore>(provider.ConsumeIntegralInRange<uint32_t>(
        0, static_cast<uint32_t>(HapPolicyCheckIgnore::ACL_IGNORE_CHECK)));
    policy.aclExtendedMap = {std::make_pair<std::string, std::string>(provider.ConsumeRandomLengthString(),
        provider.ConsumeRandomLengthString())};
}

bool UpdateHapTokenStubFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t fullTokenId = provider.ConsumeIntegral<uint64_t>();
    UpdateHapInfoParamsIdl infoIdl = {
        .appIDDesc = provider.ConsumeRandomLengthString(),
        .apiVersion = provider.ConsumeIntegral<int32_t>(),
        .isSystemApp = provider.ConsumeBool(),
        .appDistributionType = provider.ConsumeRandomLengthString(),
        .isAtomicService = provider.ConsumeBool(),
        .dataRefresh = provider.ConsumeBool(),
    };

    HapPolicyParcel hapPolicyParcel;
    InitHapPolicy(provider, hapPolicyParcel.hapPolicy);

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(fullTokenId)) {
        return false;
    }
    if (UpdateHapInfoParamsIdlBlockMarshalling(datas, infoIdl) != ERR_NONE) {
        return false;
    }
    if (!datas.WriteParcelable(&hapPolicyParcel)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UPDATE_HAP_TOKEN);
    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool InitHapTokenStubFuzzTest(FuzzedDataProvider &provider)
{
    std::string permissionName = ConsumePermissionName(provider);
    std::string bundleName = ConsumeProcessName(provider);

    HapInfoParcel hapInfoParcel;
    InitHapInfoParams(bundleName, provider, hapInfoParcel.hapInfoParameter);

    HapPolicyParcel hapPolicyParcel;
    InitHapPolicy(permissionName, bundleName, provider, hapPolicyParcel.hapPolicy);

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteParcelable(&hapInfoParcel)) {
        return false;
    }
    if (!datas.WriteParcelable(&hapPolicyParcel)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_INIT_HAP_TOKEN);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}

bool DeleteTokenStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    bool isTokenReserved = provider.ConsumeBool();

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId)) {
        return false;
    }
    if (!datas.WriteBool(isTokenReserved)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_DELETE_TOKEN);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}

bool AllocLocalTokenIDStubFuzzTest(FuzzedDataProvider &provider)
{
    std::string remoteDeviceID = provider.ConsumeRandomLengthString();
    AccessTokenID tokenId = ConsumeTokenId(provider);

    MessageParcel inData;
    inData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!inData.WriteString(remoteDeviceID) || !inData.WriteUint32(tokenId)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_ALLOC_LOCAL_TOKEN_I_D);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({}, false);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, inData, reply, option);

    return true;
}

bool ClearUserGrantedPermissionStateStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    MessageParcel sendData;
    sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!sendData.WriteUint32(tokenId)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_GRANTED_PERMISSION_STATE);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS" });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);

    return true;
}

bool DeleteRemoteDeviceTokensStubFuzzTest(FuzzedDataProvider &provider)
{
#ifdef TOKEN_SYNC_ENABLE
    std::string deviceID = provider.ConsumeRandomLengthString();

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteString(deviceID)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_DELETE_REMOTE_DEVICE_TOKENS);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((provider.ConsumeIntegral<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        (void)SetSelfTokenID(g_syncTokenId);
        uint32_t hapSize = 0;
        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        std::map<int32_t, TokenIdInfo> tokenIdAplMap;
        AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    (void)SetSelfTokenID(g_hdcdTokenID);

    return true;
#else
    return true;
#endif
}

bool GetDefPermissionStubFuzzTest(FuzzedDataProvider &provider)
{
    std::string permissionName = ConsumePermissionName(provider);
    
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteString(permissionName)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GET_DEF_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}

bool GetNativeTokenInfoStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    MessageParcel inData;
    inData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!inData.WriteUint32(tokenId)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GET_NATIVE_TOKEN_INFO);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({}, false);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, inData, reply, option);

    return true;
}

bool GrantPermissionStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);
    uint32_t flagIndex = provider.ConsumeIntegral<uint32_t>() % FLAG_LIST_SIZE;
    uint32_t flag = FLAG_LIST[flagIndex];
    int32_t grantMode = static_cast<int32_t>(provider.ConsumeIntegralInRange<int32_t>(0, 1));

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId) || !datas.WriteString(permissionName) ||
        !datas.WriteInt32(flag) || !datas.WriteInt32(grantMode)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GRANT_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.GRANT_SENSITIVE_PERMISSIONS" }, true, true);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}

bool RevokePermissionStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);
    uint32_t flagIndex = provider.ConsumeIntegral<uint32_t>() % FLAG_LIST_SIZE;
    uint32_t flag = FLAG_LIST[flagIndex];
    int32_t grantMode = static_cast<int32_t>(provider.ConsumeIntegralInRange<int32_t>(0, 1));

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId) || !datas.WriteString(permissionName) ||
        !datas.WriteInt32(flag) || !datas.WriteInt32(grantMode)) {
        return false;
    }
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_REVOKE_PERMISSION);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS" }, true, true);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

    return true;
}

#ifdef SUPPORT_MANAGE_USER_POLICY
static void ClearUserPolicy(const string& permission)
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(1)) {
        return;
    }
    if (!datas.WriteString(permission)) {
        return;
    }
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_POLICY), datas, reply, option);
}

bool SetUserPolicyStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = EnsureManageUserPolicyTestToken();
    if (tokenId == INVALID_TOKENID) {
        return false;
    }

    std::string permission = provider.ConsumeBool() ? VALID_USER_POLICY_PERMISSION : ConsumePermissionName(provider);

    UserPermissionPolicyIdl dataBlock;
    dataBlock.permissionName = permission;
    UserPolicyIdl userPolicyIdl;
    userPolicyIdl.userId = provider.ConsumeBool() ? VALID_USER_POLICY_USER_ID :
        provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX),
    userPolicyIdl.isRestricted = provider.ConsumeBool();
    dataBlock.userPolicyList.emplace_back(userPolicyIdl);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(1)) {
        return false;
    }
    if (UserPermissionPolicyIdlBlockMarshalling(datas, dataBlock) != ERR_NONE) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_SET_USER_POLICY);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_USER_POLICY" });
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    ClearUserPolicy(VALID_USER_POLICY_PERMISSION);

    return true;
}
#endif

bool VerifyAccessTokenStubFuzzTest(FuzzedDataProvider &provider)
{
    AccessTokenID tokenId = ConsumeTokenId(provider);
    std::string permissionName = ConsumePermissionName(provider);

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(tokenId) || !datas.WriteString(permissionName)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN);

    MessageParcel reply;
    MessageOption option;
    uint64_t fulltokenId =
        static_cast<uint64_t>(ConsumeTokenId(provider)) | (provider.ConsumeBool() ? FUZZ_SYSTEM_APP_MASK : 0);
    (void)SetSelfTokenID(fulltokenId);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    (void)SetSelfTokenID(g_hdcdTokenID);
    return true;
}

bool ResetDatabaseRecoveryStatusStubFuzzTest()
{
    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" }, false);
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_RESET_DATABASE_RECOVERY_STATUS);
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);
    return true;
}

void TokenSyncStubFuzzTest()
{
    RegisterTokenSyncCallback();
    UnRegisterTokenSyncCallback();
    if (g_selfTokenId != 0) {
        (void)SetSelfTokenID(g_selfTokenId);
    }
}

static GenericValues BuildUndefinedInfoRow(int32_t tokenId, const string& permissionName, int32_t acl,
    const string& appDistributionType, const string& value)
{
    GenericValues row;
    row.Put(TokenFiledConst::FIELD_TOKEN_ID, tokenId);
    row.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    row.Put(TokenFiledConst::FIELD_ACL, acl);
    row.Put(TokenFiledConst::FIELD_APP_DISTRIBUTION_TYPE, appDistributionType);
    row.Put(TokenFiledConst::FIELD_VALUE, value);
    return row;
}

static void ReplaceUndefinedInfo(const vector<GenericValues>& rows)
{
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
    addInfo.addValues = rows;
    vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

static void SeedMismatchedPermDefVersion()
{
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    addValue.Put(TokenFiledConst::FIELD_VALUE, MISMATCHED_PERM_DEF_VERSION);
    addInfo.addValues.emplace_back(addValue);
    vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    vector<AddInfo> addInfoVec;
    addInfoVec.emplace_back(addInfo);
    (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

static void ClearUndefinedInfoLeftovers(int32_t tokenId)
{
    ReplaceUndefinedInfo({});
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_PERMISSION_STATE;
    delInfo.delValue.Put(TokenFiledConst::FIELD_TOKEN_ID, tokenId);
    vector<DelInfo> delInfoVec;
    delInfoVec.emplace_back(delInfo);
    vector<AddInfo> addInfoVec;
    (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(static_cast<AccessTokenID>(tokenId));
}

// Trigger the service init path once: seed a mismatched non-empty permission definition version and
// undefined permission rows, so both the isUpdate and the !dbPermDefVersion.empty() branches in
// HandlePermDefUpdate are taken and HandleHapUndefinedInfo is reached through the natural path.
static void TriggerPermDefUpdateForFuzz()
{
    vector<GenericValues> rows;
    rows.emplace_back(
        BuildUndefinedInfoRow(UNDEFINED_INFO_TOKEN_ID, UNDEFINED_USER_GRANT_PERM, 1, "os_integration", ""));
    rows.emplace_back(
        BuildUndefinedInfoRow(UNDEFINED_INFO_TOKEN_ID, UNDEFINED_SYSTEM_GRANT_PERM, 1, "os_integration", ""));
    ReplaceUndefinedInfo(rows);
    SeedMismatchedPermDefVersion();

    map<int32_t, TokenIdInfo> tokenIdAplMap;
    TokenIdInfo tokenInfo = { APL_SYSTEM_BASIC, true };
    tokenIdAplMap[UNDEFINED_INFO_TOKEN_ID] = tokenInfo;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->HandlePermDefUpdate(tokenIdAplMap);

    sleep(ASYNC_DB_WAIT_SECONDS); // wait for UpdateDatabaseAsync to write the current version back
    ClearUndefinedInfoLeftovers(UNDEFINED_INFO_TOKEN_ID);
}

// Cover HandlePermDefUpdate and HandleHapUndefinedInfo which are only reachable from service init.
void AccessTokenServiceInitFuzz(FuzzedDataProvider &provider)
{
    if (!g_isPermDefUpdateTriggered) {
        g_isPermDefUpdateTriggered = true;
        TriggerPermDefUpdateForFuzz();
    }

    int32_t tokenId = provider.ConsumeIntegral<int32_t>();
    string permissionName = ConsumePermissionName(provider);
    int32_t acl = provider.ConsumeIntegral<int32_t>();
    string appDistributionType = provider.ConsumeRandomLengthString();
    string permValue = provider.ConsumeRandomLengthString();
    TokenIdInfo fuzzTokenInfo = { provider.ConsumeIntegral<int32_t>(), provider.ConsumeBool() };
    map<int32_t, TokenIdInfo> tokenIdAplMap;
    tokenIdAplMap[tokenId] = fuzzTokenInfo;
    TokenIdInfo fixedTokenInfo = { APL_SYSTEM_BASIC, true };
    tokenIdAplMap[UNDEFINED_INFO_TOKEN_ID] = fixedTokenInfo; // keep the fixed valid rows alive

    vector<GenericValues> rows;
    rows.emplace_back(
        BuildUndefinedInfoRow(UNDEFINED_INFO_TOKEN_ID, UNDEFINED_USER_GRANT_PERM, 1, "os_integration", ""));
    rows.emplace_back(
        BuildUndefinedInfoRow(UNDEFINED_INFO_TOKEN_ID, UNDEFINED_SYSTEM_GRANT_PERM, 1, "os_integration", ""));
    if ((tokenId != UNDEFINED_INFO_TOKEN_ID) || ((permissionName != UNDEFINED_USER_GRANT_PERM) &&
        (permissionName != UNDEFINED_SYSTEM_GRANT_PERM))) { // avoid primary key conflict with fixed rows
        rows.emplace_back(BuildUndefinedInfoRow(tokenId, permissionName, acl, appDistributionType, permValue));
    }
    ReplaceUndefinedInfo(rows);

    vector<DelInfo> delInfoVec;
    vector<AddInfo> addInfoVec;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->HandleHapUndefinedInfo(
        tokenIdAplMap, delInfoVec, addInfoVec);

    (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(
        static_cast<AccessTokenID>(UNDEFINED_INFO_TOKEN_ID));
    (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(static_cast<AccessTokenID>(tokenId));
}

void AccessTokenStubFuzzTest(FuzzedDataProvider &provider)
{
    GetVersion();
    GetPermissionManagerInfo();
    (void)ResetDatabaseRecoveryStatusStubFuzzTest();
    (void)InitHapTokenStubFuzzTest(provider);
    (void)UpdateHapTokenStubFuzzTest(provider);
    (void)DeleteTokenStubFuzzTest(provider);
    (void)AllocLocalTokenIDStubFuzzTest(provider);
    (void)ClearUserGrantedPermissionStateStubFuzzTest(provider);
    (void)DeleteRemoteDeviceTokensStubFuzzTest(provider);
    (void)GetDefPermissionStubFuzzTest(provider);
    (void)GetNativeTokenInfoStubFuzzTest(provider);
    (void)GrantPermissionStubFuzzTest(provider);
    (void)RevokePermissionStubFuzzTest(provider);
#ifdef SUPPORT_MANAGE_USER_POLICY
    (void)SetUserPolicyStubFuzzTest(provider);
#endif
    (void)VerifyAccessTokenStubFuzzTest(provider);
}

bool FuzzTest(FuzzedDataProvider &provider)
{
    TokenSyncStubFuzzTest();
    AccessTokenServiceInitFuzz(provider);
    AccessTokenStubFuzzTest(provider);
    return true;
}

void Initialize()
{
    (void)DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->AccessTokenServiceParamSet();
    g_selfTokenId = GetSelfTokenID();
    g_hdcdTokenID = AccessTokenKit::GetNativeTokenId("hdcd");
    g_syncTokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTest(provider);
    return 0;
}
