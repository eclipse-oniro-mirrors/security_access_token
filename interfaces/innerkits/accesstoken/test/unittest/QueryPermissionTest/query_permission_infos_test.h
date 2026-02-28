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

#ifndef QUERY_PERMISSION_INFOS_TEST_H
#define QUERY_PERMISSION_INFOS_TEST_H

#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "access_token.h"
#include "permission_status.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * @brief Test class for QueryPermissionStatus functionality
 *
 * This test class validates the permission status query interfaces:
 * 1. QueryStatusByPermission - Query applications by permission names (with onlyHap filter)
 * 2. QueryStatusByTokenID - Query permission status by TokenIDs (HAP applications only)
 *
 * Testing follows TDD (Test-Driven Development) approach:
 * - Red: Write failing test first
 * - Green: Write minimal code to pass test
 * - Refactor: Improve code while keeping tests passing
 */
class QueryPermissionInfosTest : public testing::Test {
public:
    QueryPermissionInfosTest() = default;
    ~QueryPermissionInfosTest() = default;

    /**
     * @brief Setup test environment before each test
     */
    static void SetUpTestCase();

    /**
     * @brief Cleanup test environment after each test
     */
    static void TearDownTestCase();

    /**
     * @brief Setup individual test
     */
    void SetUp() override;

    /**
     * @brief Teardown individual test
     */
    void TearDown() override;

protected:
    /**
     * @brief Prepare test HAP token with specified permissions
     * @param bundleName Bundle name for test HAP
     * @param permissions List of permissions to request
     * @param isSystemApp Whether the HAP is a system app
     * @param apl APL (Ability Privilege Level) for the HAP
     * @return Created AccessTokenID
     */
    AccessTokenID PrepareTestHap(const std::string& bundleName,
                                   const std::vector<std::string>& permissions,
                                   bool isSystemApp = true,
                                   ATokenAplEnum apl = APL_NORMAL);

    /**
     * @brief Cleanup test HAP token
     * @param tokenID TokenID to delete
     */
    void CleanupTestHap(AccessTokenID tokenID);

    static uint64_t selfShellTokenId_;
    static std::mutex testMutex_;
    static MockHapToken* mock_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // QUERY_PERMISSION_INFOS_TEST_H
