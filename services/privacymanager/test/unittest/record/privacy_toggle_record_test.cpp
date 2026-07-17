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

#include <gtest/gtest.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#define private public
#include "permission_record_manager.h"
#undef private

#include "constant.h"
#include "permission_used_record_db.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_test_common.h"
#include "time_util.h"
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
#include "errors.h"
#include "os_account_manager_lite.h"
#endif
#ifdef REMOTE_PRIVACY_ENABLE
#include "remote_permission_used_record_db.h"
#endif

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string TOGGLE_STATUS_TABLE = "permission_used_record_toggle_status_table";
static constexpr int32_t TEST_USER_ID_1 = 1;
static constexpr int32_t TEST_USER_ID_10 = 10;
static constexpr int32_t TEST_INVALID_USER_ID = -1;
static constexpr int32_t TEST_INVALID_USER_ID_20000 = 20000;
static constexpr int32_t LEGACY_SUBPROFILE_ID = -1;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
static AccessTokenID g_selfTokenId = 0;
static MockNativeToken* g_mock = nullptr;

class PrivacyToggleStatusMapGuard final {
public:
    explicit PrivacyToggleStatusMapGuard(int32_t userID = TEST_INVALID_USER_ID)
        : userID_(userID)
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecToggleStatusMutex_);
        originalMap_ = PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_;
        GenericValues emptyCondition;
        (void)PermissionUsedRecordDb::GetInstance().Query(
            PermissionUsedRecordDb::DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS, emptyCondition, originalRecords_);
        ResetToggleStatusTable();
        if (userID_ >= 0) {
            const std::string legacyKey = std::to_string(userID_);
            const std::string subProfileKeyPrefix = legacyKey + "_";
            auto iter = PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_.begin();
            while (iter != PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_.end()) {
                if (iter->first == legacyKey || iter->first.find(subProfileKeyPrefix) == 0) {
                    iter = PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_.erase(iter);
                } else {
                    ++iter;
                }
            }
        }
    }

    ~PrivacyToggleStatusMapGuard()
    {
        ResetToggleStatusTable();
        if (!originalRecords_.empty()) {
            (void)PermissionUsedRecordDb::GetInstance().Add(
                PermissionUsedRecordDb::DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS, originalRecords_);
        }
        {
            std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecToggleStatusMutex_);
            PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_ = originalMap_;
        }
    }

private:
    void ResetToggleStatusTable()
    {
        (void)PermissionUsedRecordDb::GetInstance().ExecuteSql("drop table if exists " + TOGGLE_STATUS_TABLE);
        (void)PermissionUsedRecordDb::GetInstance().ExecuteSql("create table " + TOGGLE_STATUS_TABLE + " ("
            "user_id integer not null,"
            "sub_profile_id integer default -1,"
            "status integer not null,"
            "primary key(user_id, sub_profile_id))");
    }

    int32_t userID_;
    std::map<std::string, bool> originalMap_;
    std::vector<GenericValues> originalRecords_;
};

std::string GetToggleStatusMapKey(int32_t userID, int32_t subProfileId)
{
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
    if (subProfileId >= 0) {
        return std::to_string(userID) + "_" + std::to_string(subProfileId);
    }
#endif
    return std::to_string(userID);
}

void VerifyToggleStatusRecord(int32_t userID, int32_t subProfileId, bool expectedStatus)
{
    GenericValues condition;
    condition.Put(PrivacyFiledConst::FIELD_USER_ID, userID);
    condition.Put(PrivacyFiledConst::FIELD_SUB_PROFILE_ID, subProfileId);
    std::vector<GenericValues> records;
    ASSERT_EQ(PermissionUsedRecordDb::SUCCESS, PermissionUsedRecordDb::GetInstance().Query(
        PermissionUsedRecordDb::DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS, condition, records));
    ASSERT_EQ(1, static_cast<int32_t>(records.size()));
    EXPECT_EQ(expectedStatus, static_cast<bool>(records[0].GetInt(PrivacyFiledConst::FIELD_STATUS)));
}

void VerifyToggleStatusRecordNotExist(int32_t userID, int32_t subProfileId)
{
    GenericValues condition;
    condition.Put(PrivacyFiledConst::FIELD_USER_ID, userID);
    condition.Put(PrivacyFiledConst::FIELD_SUB_PROFILE_ID, subProfileId);
    std::vector<GenericValues> records;
    ASSERT_EQ(PermissionUsedRecordDb::SUCCESS, PermissionUsedRecordDb::GetInstance().Query(
        PermissionUsedRecordDb::DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS, condition, records));
    EXPECT_TRUE(records.empty());
}

void VerifyToggleStatusMapValue(int32_t userID, int32_t subProfileId, bool expectedStatus)
{
    std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecToggleStatusMutex_);
    const auto& statusMap = PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_;
    auto iter = statusMap.find(GetToggleStatusMapKey(userID, subProfileId));
    ASSERT_NE(statusMap.end(), iter);
    EXPECT_EQ(expectedStatus, iter->second);
}

void VerifyToggleStatusMapNotExist(int32_t userID, int32_t subProfileId)
{
    std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecToggleStatusMutex_);
    const auto& statusMap = PermissionRecordManager::GetInstance().permUsedRecToggleStatusMap_;
    EXPECT_EQ(statusMap.end(), statusMap.find(GetToggleStatusMapKey(userID, subProfileId)));
}
}

class PrivacyToggleRecordTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
};

void PrivacyToggleRecordTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
    g_mock = new (std::nothrow) MockNativeToken("privacy_service");
    ASSERT_NE(nullptr, g_mock);
}

void PrivacyToggleRecordTest::TearDownTestCase()
{
    PrivacyTestCommon::ResetTestEvironment();
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
}

void PrivacyToggleRecordTest::SetUp()
{
    PermissionRecordManager::GetInstance().Init();
    PermissionRecordManager::GetInstance().Register();
}

/*
 * @tc.name:SetPermissionUsedRecordToggleStatus001
 * @tc.desc: PermissionRecordManager::SetPermissionUsedRecordToggleStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    int32_t ret = PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID, true, LEGACY_SUBPROFILE_ID);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);

    ret = PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID_20000, true, LEGACY_SUBPROFILE_ID);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);
}

/*
 * @tc.name:GetPermissionUsedRecordToggleStatus001
 * @tc.desc: PermissionRecordManager::GetPermissionUsedRecordToggleStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, GetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    bool status = true;
    int32_t ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID, status, LEGACY_SUBPROFILE_ID);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);

    ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_INVALID_USER_ID_20000, status, LEGACY_SUBPROFILE_ID);
    EXPECT_EQ(ret, PrivacyError::ERR_PARAM_INVALID);
}

/*
 * @tc.name:SetPermissionUsedRecordToggleStatusWithLegacySubProfileId001
 * @tc.desc: PermissionRecordManager sets and gets legacy subProfile toggle status by userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithLegacySubProfileId001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(TEST_USER_ID_1);
    bool status = true;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, false, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, status, LEGACY_SUBPROFILE_ID));
    EXPECT_FALSE(status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, true, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, status, LEGACY_SUBPROFILE_ID));
    EXPECT_TRUE(status);
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithLegacySubProfileId002
 * @tc.desc: PermissionRecordManager keeps query, toggle map and database state consistent when restoring default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithLegacySubProfileId002, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(TEST_USER_ID_1);
    bool status = false;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, status, LEGACY_SUBPROFILE_ID));
    EXPECT_TRUE(status);
    VerifyToggleStatusMapNotExist(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID);
    VerifyToggleStatusRecordNotExist(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, false, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, status, LEGACY_SUBPROFILE_ID));
    EXPECT_FALSE(status);
    VerifyToggleStatusMapValue(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID, false);
    VerifyToggleStatusRecord(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID, false);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, true, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_1, status, LEGACY_SUBPROFILE_ID));
    EXPECT_TRUE(status);
    VerifyToggleStatusMapNotExist(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID);
    VerifyToggleStatusRecordNotExist(TEST_USER_ID_1, LEGACY_SUBPROFILE_ID);
}

/*
 * @tc.name:UpdatePermUsedRecToggleStatusMap001
 * @tc.desc: PermissionRecordManager::test UpdatePermUsedRecToggleStatusMap and CheckPermissionUsedRecordToggleStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, UpdatePermUsedRecToggleStatusMap001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;
    bool checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID);
    EXPECT_TRUE(checkStatus);

    bool ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID, false);
    checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(checkStatus);

    ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID, false);
    EXPECT_FALSE(ret);

    ret = PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID, true);
    checkStatus = PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_10, LEGACY_SUBPROFILE_ID);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(checkStatus);
}

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
static constexpr int32_t ACCOUNT_OWNER_USER_ID = 0;
static constexpr int32_t TEST_USER_ID_11 = 11;
static constexpr int32_t TEST_USER_ID_12 = 12;
static constexpr int32_t TEST_USER_ID_14 = 14;
static constexpr int32_t TEST_USER_ID_15 = 15;
static constexpr int32_t TEST_USER_ID_100 = 100;
static constexpr int32_t INVALID_NEGATIVE_SUBPROFILE_ID = -2;
static constexpr int32_t SUBPROFILE_ID_TEN = 10;
static constexpr int32_t SUBPROFILE_ID_ELEVEN = 11;
static constexpr int32_t SUBPROFILE_INDEX_ZERO = 0;
static constexpr int32_t REMOTE_RECORD_QUERY_LIMIT = 100;

class PermissionRecordCacheGuard final {
public:
    PermissionRecordCacheGuard()
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecMutex_);
        originalCache_ = PermissionRecordManager::GetInstance().permUsedRecList_;
        PermissionRecordManager::GetInstance().permUsedRecList_.clear();
    }

    ~PermissionRecordCacheGuard()
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecMutex_);
        PermissionRecordManager::GetInstance().permUsedRecList_ = originalCache_;
    }

private:
    std::vector<PermissionRecordCache> originalCache_;
};

#ifdef REMOTE_PRIVACY_ENABLE
class RemotePermissionRecordGuard final {
public:
    explicit RemotePermissionRecordGuard(int32_t userID) : userID_(userID)
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        originalCache_ = PermissionRecordManager::GetInstance().remotePermUsedRecList_;
        PermissionRecordManager::GetInstance().remotePermUsedRecList_.clear();

        GenericValues emptyCondition;
        (void)RemotePermUsedRecordDbManager::GetInstance().FindByConditions(
            userID_, {}, emptyCondition, originalRecords_, REMOTE_RECORD_QUERY_LIMIT);
        (void)RemotePermUsedRecordDbManager::GetInstance().Remove(userID_, emptyCondition);
    }

    ~RemotePermissionRecordGuard()
    {
        GenericValues emptyCondition;
        (void)RemotePermUsedRecordDbManager::GetInstance().Remove(userID_, emptyCondition);
        if (!originalRecords_.empty()) {
            (void)RemotePermUsedRecordDbManager::GetInstance().Add(userID_, originalRecords_);
        }

        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        PermissionRecordManager::GetInstance().remotePermUsedRecList_ = originalCache_;
    }

private:
    int32_t userID_;
    std::vector<RemotePermissionRecordCache> originalCache_;
    std::vector<GenericValues> originalRecords_;
};

RemotePermissionRecord BuildRemotePermissionRecord(
    const std::string& deviceId, const std::string& deviceName, int32_t userID, int32_t subProfileId)
{
    RemotePermissionRecord record;
    record.deviceId = deviceId;
    record.deviceName = deviceName;
    record.opCode = Constant::OP_CAMERA;
    record.timestamp = AccessToken::TimeUtil::GetCurrentTimestamp();
    record.accessCount = 1;
    record.rejectCount = 0;
    record.userId = userID;
    record.subProfileId = subProfileId;
    return record;
}
#endif

/*
 * @tc.name: UpdatePermUsedRecToggleStatusMapWithSubProfileId001
 * @tc.desc: PermissionRecordManager keeps legacy and subProfile toggle cache keys isolated.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, UpdatePermUsedRecToggleStatusMapWithSubProfileId001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;
    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_11, LEGACY_SUBPROFILE_ID, false));
    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN, true));

    EXPECT_FALSE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_11, LEGACY_SUBPROFILE_ID));
    EXPECT_TRUE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN));
    EXPECT_TRUE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_11, SUBPROFILE_ID_ELEVEN));
}

/*
 * @tc.name: UpdatePermUsedRecToggleStatusMapWithSubProfileId002
 * @tc.desc: PermissionRecordManager returns false when subProfile toggle cache already has the same status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, UpdatePermUsedRecToggleStatusMapWithSubProfileId002, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;

    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN, false));
    EXPECT_FALSE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN, false));
    EXPECT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN, true));
    EXPECT_TRUE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_11, SUBPROFILE_ID_TEN));
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId008
 * @tc.desc: PermissionRecordManager returns success without database update when subProfile status is unchanged.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId008, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = false;

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_TRUE(status);
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: UpdatePermUsedRecToggleStatusMapWithNegativeSubProfileId001
 * @tc.desc: PermissionRecordManager maps negative subProfileId to legacy toggle cache key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, UpdatePermUsedRecToggleStatusMapWithNegativeSubProfileId001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;
    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_12, LEGACY_SUBPROFILE_ID, false));

    EXPECT_FALSE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_12, LEGACY_SUBPROFILE_ID));
    EXPECT_FALSE(PermissionRecordManager::GetInstance().CheckPermissionUsedRecordToggleStatus(
        TEST_USER_ID_12, INVALID_NEGATIVE_SUBPROFILE_ID));
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId001
 * @tc.desc: PermissionRecordManager isolates legal subProfileId toggle status by userId + subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = false;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);

    status = false;
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_ELEVEN));
    EXPECT_TRUE(status);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_ELEVEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_TRUE(status);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_ELEVEN));
    EXPECT_FALSE(status);
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId002
 * @tc.desc: PermissionRecordManager allows subProfile toggle write after legacy mode is reset to default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId002, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = true;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, LEGACY_SUBPROFILE_ID));

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);
}

/*
 * @tc.name: GetPermissionUsedRecordToggleStatusWithSubProfileId001
 * @tc.desc: PermissionRecordManager returns legacy toggle status when querying subProfile and legacy mode exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, GetPermissionUsedRecordToggleStatusWithSubProfileId001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = true;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, LEGACY_SUBPROFILE_ID));
    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    int32_t ret = PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN);
    ResetMockOsAccountManagerLite();

    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_FALSE(status);
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId003
 * @tc.desc: PermissionRecordManager returns subProfile not exist when subProfileId is not under current user.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId003, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;
    bool status = true;

    SetMockOsAccountLocalIdForSubProfile(TEST_USER_ID_15, ERR_OK);
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            TEST_USER_ID_14, false, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_SUBPROFILE_NOT_EXIST,
        PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
            TEST_USER_ID_14, status, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId004
 * @tc.desc: PermissionRecordManager returns service abnormal when account query fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId004, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard;
    bool status = true;

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_INVALID_VALUE);
    EXPECT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL,
        PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId005
 * @tc.desc: PermissionRecordManager keeps subProfile toggle path when account query succeeds and user matches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId005, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = true;

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    EXPECT_EQ(RET_SUCCESS,
        PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId006
 * @tc.desc: PermissionRecordManager returns conflict until subProfile mode is reset to default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId006, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = true;

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    int32_t ret = PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN);
    ResetMockOsAccountManagerLite();
    EXPECT_EQ(RET_SUCCESS, ret);

    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, true, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, status, LEGACY_SUBPROFILE_ID));

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, LEGACY_SUBPROFILE_ID));
    EXPECT_FALSE(status);
}

#ifdef REMOTE_PRIVACY_ENABLE
/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId007
 * @tc.desc: PermissionRecordManager removes remote records only for the closed subProfile toggle key.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId007, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard toggleGuard(TEST_USER_ID_100);
    RemotePermissionRecordGuard remoteGuard(TEST_USER_ID_100);

    RemotePermissionRecord targetRecord = BuildRemotePermissionRecord(
        "subProfileTargetId", "subProfileTargetName", TEST_USER_ID_100, SUBPROFILE_ID_TEN);
    RemotePermissionRecord otherSubProfileRecord = BuildRemotePermissionRecord(
        "subProfileOtherId", "subProfileOtherName", TEST_USER_ID_100, SUBPROFILE_ID_ELEVEN);

    RemotePermissionRecordCache targetCache;
    targetCache.record = targetRecord;
    RemotePermissionRecordCache otherCache;
    otherCache.record = otherSubProfileRecord;
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        PermissionRecordManager::GetInstance().remotePermUsedRecList_.emplace_back(targetCache);
        PermissionRecordManager::GetInstance().remotePermUsedRecList_.emplace_back(otherCache);
    }

    GenericValues targetValue;
    GenericValues otherValue;
    RemotePermissionRecord::TranslationIntoGenericValues(targetRecord, targetValue);
    RemotePermissionRecord::TranslationIntoGenericValues(otherSubProfileRecord, otherValue);
    std::vector<GenericValues> values = { targetValue, otherValue };
    ASSERT_EQ(Constant::SUCCESS, RemotePermUsedRecordDbManager::GetInstance().Add(TEST_USER_ID_100, values));

    SetMockOsAccountLocalIdForSubProfile(TEST_USER_ID_100, ERR_OK);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_100, false, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();

    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        ASSERT_EQ(1U, PermissionRecordManager::GetInstance().remotePermUsedRecList_.size());
        EXPECT_EQ(SUBPROFILE_ID_ELEVEN,
            PermissionRecordManager::GetInstance().remotePermUsedRecList_[0].record.subProfileId);
    }

    GenericValues queryCondition;
    std::vector<GenericValues> results;
    ASSERT_EQ(Constant::SUCCESS, RemotePermUsedRecordDbManager::GetInstance().FindByConditions(
        TEST_USER_ID_100, {}, queryCondition, results, REMOTE_RECORD_QUERY_LIMIT));
    ASSERT_EQ(1U, results.size());
    EXPECT_EQ(SUBPROFILE_ID_ELEVEN, results[0].GetInt(PrivacyFiledConst::FIELD_SUB_PROFILE_ID));
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId011
 * @tc.desc: PermissionRecordManager removes only legacy remote records when legacy toggle is closed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId011, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard toggleGuard(TEST_USER_ID_100);
    RemotePermissionRecordGuard remoteGuard(TEST_USER_ID_100);

    RemotePermissionRecord legacyRecord = BuildRemotePermissionRecord(
        "legacyTargetId", "legacyTargetName", TEST_USER_ID_100, LEGACY_SUBPROFILE_ID);
    RemotePermissionRecord subProfileRecord = BuildRemotePermissionRecord(
        "subProfileTargetId", "subProfileTargetName", TEST_USER_ID_100, SUBPROFILE_ID_TEN);
    RemotePermissionRecordCache legacyCache;
    legacyCache.record = legacyRecord;
    RemotePermissionRecordCache subProfileCache;
    subProfileCache.record = subProfileRecord;
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        PermissionRecordManager::GetInstance().remotePermUsedRecList_.emplace_back(legacyCache);
        PermissionRecordManager::GetInstance().remotePermUsedRecList_.emplace_back(subProfileCache);
    }

    GenericValues legacyValue;
    GenericValues subProfileValue;
    RemotePermissionRecord::TranslationIntoGenericValues(legacyRecord, legacyValue);
    RemotePermissionRecord::TranslationIntoGenericValues(subProfileRecord, subProfileValue);
    ASSERT_EQ(Constant::SUCCESS, RemotePermUsedRecordDbManager::GetInstance().Add(
        TEST_USER_ID_100, { legacyValue, subProfileValue }));

    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        TEST_USER_ID_100, false, LEGACY_SUBPROFILE_ID));

    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().remotePermUsedRecMutex_);
        ASSERT_EQ(1U, PermissionRecordManager::GetInstance().remotePermUsedRecList_.size());
        EXPECT_EQ(SUBPROFILE_ID_TEN,
            PermissionRecordManager::GetInstance().remotePermUsedRecList_[0].record.subProfileId);
    }

    GenericValues queryCondition;
    std::vector<GenericValues> results;
    ASSERT_EQ(Constant::SUCCESS, RemotePermUsedRecordDbManager::GetInstance().FindByConditions(
        TEST_USER_ID_100, {}, queryCondition, results, REMOTE_RECORD_QUERY_LIMIT));
    ASSERT_EQ(1U, results.size());
    EXPECT_EQ(SUBPROFILE_ID_TEN, results[0].GetInt(PrivacyFiledConst::FIELD_SUB_PROFILE_ID));
}
#endif

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId009
 * @tc.desc: PermissionRecordManager removes local history records for target subProfile when toggle is closed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId009, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard toggleGuard(ACCOUNT_OWNER_USER_ID);
    PermissionRecordCacheGuard recordGuard;
    HapInfoParams hapInfo = {
        .userID = ACCOUNT_OWNER_USER_ID,
        .bundleName = "SetPermissionUsedRecordToggleStatusWithSubProfileId009",
        .instIndex = SUBPROFILE_INDEX_ZERO,
        .appIDDesc = "privacy_toggle_record_test",
        .apiVersion = PrivacyTestCommon::DEFAULT_API_VERSION,
        .isSystemApp = true,
    };
    HapPolicyParams hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "privacy_toggle_record_test_domain",
    };
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(hapInfo, hapPolicy);
    const AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = CAMERA_PERMISSION_NAME;
    info.successCount = 1;
    info.failCount = 0;

    SetMockOsAccountSubProfileId(SUBPROFILE_ID_TEN, ERR_OK);
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecMutex_);
        ASSERT_FALSE(PermissionRecordManager::GetInstance().permUsedRecList_.empty());
    }

    MockNativeToken nativeMock("privacy_service");
    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    SetMockOsAccountSubProfileIndex(SUBPROFILE_INDEX_ZERO, ERR_OK);
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));

    {
        std::lock_guard<std::mutex> lock(PermissionRecordManager::GetInstance().permUsedRecMutex_);
        EXPECT_TRUE(PermissionRecordManager::GetInstance().permUsedRecList_.empty());
    }
    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenId));
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileId010
 * @tc.desc: PermissionRecordManager keeps query, toggle map and database state unchanged after mode conflicts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, SetPermissionUsedRecordToggleStatusWithSubProfileId010, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    bool status = true;

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, LEGACY_SUBPROFILE_ID));
    VerifyToggleStatusMapValue(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID, false);
    VerifyToggleStatusRecord(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID, false);

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, LEGACY_SUBPROFILE_ID));
    EXPECT_FALSE(status);
    VerifyToggleStatusMapValue(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID, false);
    VerifyToggleStatusRecord(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID, false);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, true, LEGACY_SUBPROFILE_ID));
    VerifyToggleStatusMapNotExist(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID);
    VerifyToggleStatusRecordNotExist(ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID);

    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);
    VerifyToggleStatusMapValue(ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN, false);
    VerifyToggleStatusRecord(ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN, false);

    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, true, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, false, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecordToggleStatus(
        ACCOUNT_OWNER_USER_ID, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);
    VerifyToggleStatusMapValue(ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN, false);
    VerifyToggleStatusRecord(ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN, false);
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: AddPermissionUsedRecordWithSubProfileToggleStatus001
 * @tc.desc: AddPermissionUsedRecord respects toggle status set by userId + subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, AddPermissionUsedRecordWithSubProfileToggleStatus001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard guard(ACCOUNT_OWNER_USER_ID);
    HapInfoParams hapInfo = {
        .userID = ACCOUNT_OWNER_USER_ID,
        .bundleName = "AddPermissionUsedRecordWithSubProfileToggleStatus001",
        .instIndex = SUBPROFILE_INDEX_ZERO,
        .appIDDesc = "privacy_toggle_record_test",
        .apiVersion = PrivacyTestCommon::DEFAULT_API_VERSION,
        .isSystemApp = true,
    };
    HapPolicyParams hapPolicy = {
        .apl = APL_NORMAL,
        .domain = "privacy_toggle_record_test_domain",
    };
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(hapInfo, hapPolicy);
    const AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenId);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = CAMERA_PERMISSION_NAME;
    info.successCount = 1;
    info.failCount = 0;

    SetMockOsAccountLocalIdForSubProfile(ACCOUNT_OWNER_USER_ID, ERR_OK);
    {
        MockNativeToken nativeMock("privacy_service");
        EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, false, SUBPROFILE_ID_TEN));
    }
    SetMockOsAccountSubProfileId(SUBPROFILE_ID_TEN, ERR_OK);
    EXPECT_EQ(PrivacyError::ERR_PRIVACY_TOGGELE_RESTRICTED,
        PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    {
        MockNativeToken nativeMock("privacy_service");
        EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().SetPermissionUsedRecordToggleStatus(
            ACCOUNT_OWNER_USER_ID, true, SUBPROFILE_ID_TEN));
    }
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenId));
    ResetMockOsAccountManagerLite();
}

#ifdef REMOTE_PRIVACY_ENABLE
/*
 * @tc.name: AddRemotePermissionUsedRecordWithSubProfileToggleStatus001
 * @tc.desc: AddRemotePermissionUsedRecord respects foreground subProfile toggle status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, AddRemotePermissionUsedRecordWithSubProfileToggleStatus001, TestSize.Level0)
{
    PrivacyToggleStatusMapGuard toggleGuard(TEST_USER_ID_100);
    RemotePermissionRecordGuard remoteGuard(TEST_USER_ID_100);

    RemoteAddPermParamInfo info;
    info.deviceId = "remoteSubProfileId";
    info.deviceName = "remoteSubProfileName";
    info.permissionName = CAMERA_PERMISSION_NAME;
    info.successCount = 1;
    info.failCount = 0;

    SetMockForegroundOsAccountLocalId(TEST_USER_ID_100, ERR_OK);
    SetMockOsAccountForegroundSubProfileId(SUBPROFILE_ID_TEN, ERR_OK);
    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_100, SUBPROFILE_ID_TEN, false));
    EXPECT_EQ(PrivacyError::ERR_PRIVACY_TOGGELE_RESTRICTED,
        PermissionRecordManager::GetInstance().AddRemotePermissionUsedRecord(info));

    ASSERT_TRUE(PermissionRecordManager::GetInstance().UpdatePermUsedRecToggleStatusMap(
        TEST_USER_ID_100, SUBPROFILE_ID_TEN, true));
    EXPECT_EQ(RET_SUCCESS, PermissionRecordManager::GetInstance().AddRemotePermissionUsedRecord(info));
    ResetMockOsAccountManagerLite();
}

/*
 * @tc.name: AddRemotePermissionUsedRecordWithSubProfileToggleStatus002
 * @tc.desc: AddRemotePermissionUsedRecord returns service abnormal when foreground subProfile query fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyToggleRecordTest, AddRemotePermissionUsedRecordWithSubProfileToggleStatus002, TestSize.Level0)
{
    RemoteAddPermParamInfo info;
    info.deviceId = "remoteSubProfileErrId";
    info.deviceName = "remoteSubProfileErrName";
    info.permissionName = MICROPHONE_PERMISSION_NAME;
    info.successCount = 1;
    info.failCount = 0;

    SetMockForegroundOsAccountLocalId(TEST_USER_ID_100, ERR_OK);
    SetMockOsAccountForegroundSubProfileId(SUBPROFILE_ID_TEN, ERR_INVALID_VALUE);
    EXPECT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL,
        PermissionRecordManager::GetInstance().AddRemotePermissionUsedRecord(info));
    ResetMockOsAccountManagerLite();
}
#endif
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
