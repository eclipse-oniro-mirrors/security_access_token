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
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#include "bundle_infos_rawdata_helper.h"
#include "check_hap_sign_result_rawdata_helper.h"
#include "rawdata_buffer.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// read-side entry limit (MAX_BUNDLE_INFO_SIZE in rawdata_buffer.h)
constexpr uint32_t TEST_BUNDLE_INFO_LIMIT = 128;
constexpr uint32_t TEST_RAWDATA_MAX_SIZE = 128u * 1024 * 1024;

// copying the rawdata holders must stay a compile error: the destructor frees
// the owned buffer, so a shallow copy would double free it
static_assert(!std::is_copy_constructible<RawdataBuffer>::value, "copy ctor must stay deleted");
static_assert(!std::is_copy_assignable<RawdataBuffer>::value, "copy assign must stay deleted");
static_assert(!std::is_copy_constructible<BundleInfosRawdata>::value, "copy ctor must stay deleted");
static_assert(!std::is_copy_assignable<BundleInfosRawdata>::value, "copy assign must stay deleted");
static_assert(!std::is_copy_constructible<CheckHapSignResultRawdata>::value, "copy ctor must stay deleted");
static_assert(!std::is_copy_assignable<CheckHapSignResultRawdata>::value, "copy assign must stay deleted");

TrustedBundleInfo BuildBundleInfo(const std::string& suffix)
{
    TrustedBundleInfo info;
    info.profileData.provisionRaw = "provision-" + suffix;
    info.profileData.profileBlockLength = 4;
    info.profileData.profileBlock = {0x01, 0x02, 0x03, 0x04};
    info.profileData.appId = "appid-" + suffix;
    info.profileData.fingerprint = "fingerprint-" + suffix;
    info.profileData.organization = "org-" + suffix;
    info.profileData.isOpenHarmony = true;
    info.profileData.isEnterpriseResigned = false;
    info.moduleInfo = "module-" + suffix;
    info.sharedFiles = "shared-" + suffix;
    return info;
}

void AssertBundleInfoEq(const TrustedBundleInfo& expected, const TrustedBundleInfo& actual)
{
    EXPECT_EQ(expected.profileData.provisionRaw, actual.profileData.provisionRaw);
    EXPECT_EQ(expected.profileData.profileBlockLength, actual.profileData.profileBlockLength);
    EXPECT_EQ(expected.profileData.profileBlock, actual.profileData.profileBlock);
    EXPECT_EQ(expected.profileData.appId, actual.profileData.appId);
    EXPECT_EQ(expected.profileData.fingerprint, actual.profileData.fingerprint);
    EXPECT_EQ(expected.profileData.organization, actual.profileData.organization);
    EXPECT_EQ(expected.profileData.isOpenHarmony, actual.profileData.isOpenHarmony);
    EXPECT_EQ(expected.profileData.isEnterpriseResigned, actual.profileData.isEnterpriseResigned);
    EXPECT_EQ(expected.moduleInfo, actual.moduleInfo);
    EXPECT_EQ(expected.sharedFiles, actual.sharedFiles);
}
} // namespace

class RawdataHelperTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: RawdataRoundTrip001
 * @tc.desc: BundleInfosRawdataHelper write->read round trip keeps every field
 *           of multiple bundle infos.
 * @tc.type: FUNC
 */
HWTEST_F(RawdataHelperTest, RawdataRoundTrip001, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> infos;
    infos.emplace_back(BuildBundleInfo("first"));
    infos.emplace_back(BuildBundleInfo("second"));
    infos.emplace_back(BuildBundleInfo("third"));

    BundleInfosRawdata rawData;
    ASSERT_TRUE(BundleInfosRawdataHelper::WriteToRawData(infos, rawData));
    ASSERT_NE(nullptr, rawData.data);
    ASSERT_GT(rawData.size, 0u);

    std::vector<TrustedBundleInfo> out;
    ASSERT_TRUE(BundleInfosRawdataHelper::ReadFromRawData(rawData, out));
    ASSERT_EQ(infos.size(), out.size());
    for (size_t i = 0; i < infos.size(); ++i) {
        AssertBundleInfoEq(infos[i], out[i]);
    }
}

/**
 * @tc.name: CheckHapSignResultRoundTrip002
 * @tc.desc: CheckHapSignResultRawdataHelper write->read round trip keeps the
 *           result fields and the embedded bundle info list.
 * @tc.type: FUNC
 */
HWTEST_F(RawdataHelperTest, CheckHapSignResultRoundTrip002, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> infos;
    infos.emplace_back(BuildBundleInfo("one"));
    infos.emplace_back(BuildBundleInfo("two"));

    constexpr int32_t RESULT = 12100039;
    constexpr int32_t SESSION_ID = 42;
    HapVerifyResultInfo resultInfo;
    resultInfo.index = 7;
    resultInfo.errorCode = 12100050;

    CheckHapSignResultRawdata rawData;
    ASSERT_TRUE(CheckHapSignResultRawdataHelper::WriteToRawData(
        RESULT, SESSION_ID, infos, resultInfo, rawData));

    int32_t outResult = 0;
    int32_t outSessionId = 0;
    std::vector<TrustedBundleInfo> out;
    HapVerifyResultInfo outResultInfo;
    ASSERT_TRUE(CheckHapSignResultRawdataHelper::ReadFromRawData(
        rawData, outResult, outSessionId, out, outResultInfo));
    EXPECT_EQ(RESULT, outResult);
    EXPECT_EQ(SESSION_ID, outSessionId);
    EXPECT_EQ(resultInfo.index, outResultInfo.index);
    EXPECT_EQ(resultInfo.errorCode, outResultInfo.errorCode);
    ASSERT_EQ(infos.size(), out.size());
    for (size_t i = 0; i < infos.size(); ++i) {
        AssertBundleInfoEq(infos[i], out[i]);
    }
}

/**
 * @tc.name: RawdataCountOverLimitRejected003
 * @tc.desc: Reading a buffer whose entry count exceeds the limit
 *           (TEST_BUNDLE_INFO_LIMIT) is rejected on the read side.
 * @tc.type: FUNC
 */
HWTEST_F(RawdataHelperTest, RawdataCountOverLimitRejected003, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> infos;
    for (uint32_t i = 0; i <= TEST_BUNDLE_INFO_LIMIT; ++i) {
        infos.emplace_back(BuildBundleInfo(std::to_string(i)));
    }
    BundleInfosRawdata rawData;
    ASSERT_TRUE(BundleInfosRawdataHelper::WriteToRawData(infos, rawData));

    std::vector<TrustedBundleInfo> out;
    ASSERT_FALSE(BundleInfosRawdataHelper::ReadFromRawData(rawData, out));
}

/**
 * @tc.name: RawdataMalformedInputRejected004
 * @tc.desc: Reading rejects a default (null/zero) buffer and a malformed
 *           buffer (entry count present, payload truncated).
 * @tc.type: FUNC
 */
HWTEST_F(RawdataHelperTest, RawdataMalformedInputRejected004, TestSize.Level0)
{
    // default constructed: data == nullptr, size == 0
    BundleInfosRawdata emptyRaw;
    std::vector<TrustedBundleInfo> out;
    ASSERT_FALSE(BundleInfosRawdataHelper::ReadFromRawData(emptyRaw, out));

    CheckHapSignResultRawdata emptyResult;
    int32_t outResult = 0;
    int32_t outSessionId = 0;
    HapVerifyResultInfo outResultInfo;
    ASSERT_FALSE(CheckHapSignResultRawdataHelper::ReadFromRawData(
        emptyResult, outResult, outSessionId, out, outResultInfo));

    // malformed: count = 1 but no payload bytes follow
    BundleInfosRawdata malformed;
    malformed.size = 4; // one uint32 count field only
    const uint8_t bytes[] = {0x01, 0x00, 0x00, 0x00};
    ASSERT_EQ(0, malformed.RawDataCpy(bytes));
    ASSERT_FALSE(BundleInfosRawdataHelper::ReadFromRawData(malformed, out));
}

/**
 * @tc.name: RawdataBufferCpyGuards005
 * @tc.desc: RawDataCpy rejects a null source, a zero size and an oversized
 *           size without allocating.
 * @tc.type: FUNC
 */
HWTEST_F(RawdataHelperTest, RawdataBufferCpyGuards005, TestSize.Level0)
{
    RawdataBuffer buffer;
    const uint8_t bytes[] = {0x01, 0x02};

    // null source
    buffer.size = 2;
    EXPECT_EQ(-1, buffer.RawDataCpy(nullptr));

    // zero size
    buffer.size = 0;
    EXPECT_EQ(-1, buffer.RawDataCpy(bytes));

    // size at/over the rawdata cap
    buffer.size = TEST_RAWDATA_MAX_SIZE;
    EXPECT_EQ(-1, buffer.RawDataCpy(bytes));

    // valid copy replaces previous data cleanly
    buffer.size = 2;
    EXPECT_EQ(0, buffer.RawDataCpy(bytes));
    ASSERT_NE(nullptr, buffer.data);
    EXPECT_EQ(0, memcmp(buffer.data, bytes, sizeof(bytes)));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
