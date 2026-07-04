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

#include "bootverifyscheduler_fuzzer.h"

#include <memory>
#include <string>
#include <vector>

#include "access_token_error.h"
#include "accesstoken_info_utils.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "generic_values.h"
#include "interfaces/hap_verify.h"
#include "mock_access_token_db_operator.h"
#include "mock_app_verify_adapter.h"
#include "parameter.h"
#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "boot_verify_scheduler.h"
#include "hap_sign_verify_manager.h"
#include "permission_data_brief.h"
#undef private
#include "token_field_const.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr AccessTokenID TEST_TOKEN_ID = 0x20000001;
constexpr uint32_t TEST_UID = 20010001;
constexpr char DEFAULT_TOKEN_VERSION_VALUE = 1;
const std::string TEST_BUNDLE_NAME = "com.example.bootverifyfuzz";
const std::string TEST_PATH = "/data/app/el1/bundle/public/bootverifyfuzz.hap";

std::vector<uint8_t> BuildPersistData(const std::string& moduleRaw, const std::string& profileRaw)
{
    Security::Verify::BootstrapInfo bootstrapInfo;
    bootstrapInfo.version = 1;
    bootstrapInfo.moduleRaw = moduleRaw;
    bootstrapInfo.profileJsonRaw = profileRaw;
    std::unique_ptr<uint8_t[]> dump(bootstrapInfo.Dump());
    uint64_t size = bootstrapInfo.GetSize();
    return std::vector<uint8_t>(dump.get(), dump.get() + size);
}

GenericValues BuildHapInfoValue(AccessTokenID tokenId, uint32_t uid,
    int32_t apl = APL_NORMAL, uint32_t tokenAttr = 0, bool migrated = true)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_USER_ID, 100); // default user id is 100
    value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, TEST_BUNDLE_NAME);
    value.Put(TokenFiledConst::FIELD_API_VERSION, 12); // default api version is 12
    value.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
    value.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);
    value.Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(uid));
    value.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(DEFAULT_TOKEN_VERSION_VALUE));
    value.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenAttr));
    value.Put(TokenFiledConst::FIELD_APL, apl);
    value.Put(TokenFiledConst::FIELD_MIGRATED, migrated ? 1 : 0);
    value.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(ReservedType::NONE));
    value.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, 0);
    return value;
}

GenericValues BuildPermStateValue(AccessTokenID tokenId, const std::string& permissionName,
    PermissionState grantState = PermissionState::PERMISSION_DENIED,
    PermissionFlag grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    value.Put(TokenFiledConst::FIELD_DEVICE_ID, "");
    value.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
    value.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(grantState));
    value.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(grantFlag));
    return value;
}

GenericValues BuildBundleSignValue(const std::string& moduleName,
    const std::string& path, bool isPreInstalled, const std::vector<uint8_t>& persistData)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_BUNDLE_NAME, TEST_BUNDLE_NAME);
    value.Put(TokenFiledConst::FIELD_MODULE_NAME, moduleName);
    value.Put(TokenFiledConst::FIELD_PATH, path);
    value.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, isPreInstalled ? 1 : 0);
    value.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP));
    value.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistData);
    return value;
}

void PrepareVerifyDb(bool preInstalled)
{
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, RET_SUCCESS,
        {BuildHapInfoValue(TEST_TOKEN_ID, TEST_UID)});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, RET_SUCCESS,
        {BuildPermStateValue(TEST_TOKEN_ID, "ohos.permission.CAMERA")});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, RET_SUCCESS,
        {BuildBundleSignValue("entry", TEST_PATH, preInstalled,
            BuildPersistData(TEST_BUNDLE_NAME, TEST_BUNDLE_NAME))});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, RET_SUCCESS, {});
    SetMockDbFindResult(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, RET_SUCCESS, {});
}

} // namespace

bool BootVerifySchedulerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    auto& scheduler = BootVerifyScheduler::GetInstance();
    auto* originAdapter = HapSignVerifyManager::GetInstance().adapter_;
    auto adapter = std::make_unique<MockAppVerifyAdapter>();
    adapter->bundleName_ = TEST_BUNDLE_NAME;
    adapter->appIdentifier_ = "mock.identifier";
    adapter->appId_ = "mock.appid";
    adapter->moduleName_ = "entry";
    adapter->moduleRaw_ = TEST_BUNDLE_NAME;
    adapter->profileJsonRaw_ = TEST_BUNDLE_NAME;
    adapter->verifyIsChanged_ = true;
    adapter->bundleType_ = AppExecFwk::Spm::BundleType::APP;
    adapter->apl_ = "system_core";
    adapter->requestPermissions_.clear();
    HapSignVerifyManager::GetInstance().adapter_ = adapter.get();

    ResetMockDbState();
    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, provider.ConsumeBool() ? "1" : "0");
    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, provider.ConsumeBool() ? "1" : "0");
    PrepareVerifyDb(provider.ConsumeBool());

    AccessTokenIDManager::GetInstance().tokenIdSet_.clear();
    AccessTokenIDManager::GetInstance().reservedTokenIdSet_.clear();
    AccessTokenIDManager::GetInstance().untrustedTokenIdSet_.clear();
    PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
    scheduler.ClearBundleVerifyContext();
    scheduler.bundleSignInfoMap_.clear();
    scheduler.isAllHapBundlesVerified_.store(false);
    scheduler.uidSet_.clear();
    uint32_t hapSize = 0;
    if (scheduler.VerifyBundleSignInfoWhenStart(hapSize) == RET_SUCCESS) {
        (void)scheduler.VerifyBundleWithState(TEST_BUNDLE_NAME);
    }

    HapSignVerifyManager::GetInstance().adapter_ = originAdapter;
    SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "0");
    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "0");
    PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
    ResetMockDbState();
    scheduler.ClearBundleVerifyContext();
    scheduler.bundleSignInfoMap_.clear();
    scheduler.uidSet_.clear();
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::BootVerifySchedulerFuzzTest(data, size);
    return 0;
}
