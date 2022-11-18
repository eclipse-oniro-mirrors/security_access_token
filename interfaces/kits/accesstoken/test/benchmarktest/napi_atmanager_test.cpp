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

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <thread>
#undef private
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "permission_def.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

namespace {
int32_t TOKENID = 0;

static const std::string BENCHMARK_TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
PermissionDef PERMISSIONDEF = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

class NapiAtmanagerTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state)
    {}
    void TearDown(const ::benchmark::State &state)
    {}
};

/**
 * @tc.name: VerifyAccessTokenTestCase001
 * @tc.desc: VerifyAccessToken
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(NapiAtmanagerTest, VerifyAccessTokenTestCase001)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "NapiAtmanagerTest VerifyAccessTokenTestCase001 start!";
    for (auto _ : st) {
        EXPECT_EQ(AccessTokenKit::VerifyAccessToken(TOKENID, BENCHMARK_TEST_PERMISSION_NAME_ALPHA), -1);
    }
}

BENCHMARK_REGISTER_F(NapiAtmanagerTest, VerifyAccessTokenTestCase001)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
 * @tc.name: GetPermissionFlagsTestCase002
 * @tc.desc: GetPermissionFlags
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(NapiAtmanagerTest, GetPermissionFlagsTestCase002)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "NapiAtmanagerTest GetPermissionFlagsTestCase002 start!";
    for (auto _ : st) {
        int32_t flag;
        EXPECT_EQ(AccessTokenKit::GetPermissionFlag(TOKENID, BENCHMARK_TEST_PERMISSION_NAME_ALPHA, flag),
            AccessTokenError::ERR_PARAM_INVALID);
    }
}

BENCHMARK_REGISTER_F(NapiAtmanagerTest, GetPermissionFlagsTestCase002)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
 * @tc.name: GetDefPermissionTestCase003
 * @tc.desc: GetDefPermission
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(NapiAtmanagerTest, GetDefPermissionTestCase003)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "NapiAtmanagerTest GetDefPermissionTestCase003 start!";
    for (auto _ : st) {
        EXPECT_EQ(AccessTokenKit::GetDefPermission(BENCHMARK_TEST_PERMISSION_NAME_ALPHA, PERMISSIONDEF),
            AccessTokenError::ERR_PERMISSION_NOT_EXIT);
    }
}

BENCHMARK_REGISTER_F(NapiAtmanagerTest, GetDefPermissionTestCase003)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
 * @tc.name: RevokeUserGrantedPermissionTestCase004
 * @tc.desc: RevokeUserGrantedPermission
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(NapiAtmanagerTest, RevokeUserGrantedPermissionTestCase004)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "NapiAtmanagerTest RevokeUserGrantedPermissionTestCase004 start!";
    for (auto _ : st) {
        EXPECT_EQ(AccessTokenKit::RevokePermission(TOKENID, BENCHMARK_TEST_PERMISSION_NAME_ALPHA, 0),
            AccessTokenError::ERR_PARAM_INVALID);
    }
}

BENCHMARK_REGISTER_F(NapiAtmanagerTest, RevokeUserGrantedPermissionTestCase004)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
 * @tc.name: GrantPermissionTestCase005
 * @tc.desc: GrantPermission
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(NapiAtmanagerTest, GrantPermissionTestCase005)(
    benchmark::State &st)
{
    GTEST_LOG_(INFO) << "NapiAtmanagerTest GrantPermissionTestCase005 start!";
    for (auto _ : st) {
        EXPECT_EQ(AccessTokenKit::GrantPermission(TOKENID, BENCHMARK_TEST_PERMISSION_NAME_ALPHA, 0),
            AccessTokenError::ERR_PARAM_INVALID);
    }
}

BENCHMARK_REGISTER_F(NapiAtmanagerTest, GrantPermissionTestCase005)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();
} // namespace

BENCHMARK_MAIN();