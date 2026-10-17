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

#ifndef DELETE_IDENTITY_MOCK_TEST_H
#define DELETE_IDENTITY_MOCK_TEST_H

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "accesstoken_kit.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class DeleteIdentityMockTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    void InstallHap(const std::vector<std::string>& hapPaths, const HapBaseInfo& baseInfo,
        const BundlePolicy& bundlePolicy, Identity& identity);

    void CloneApp(const std::string& hapPath, const HapBaseInfo& baseInfo,
        const BundlePolicy& bundlePolicy, Identity& identity);

    bool VerifyTokenDeletedFromDatabase(AccessTokenID tokenId);

    bool VerifyTokenExistsInDatabase(AccessTokenID tokenId, int32_t& uid, int32_t& reserved);

    bool VerifyBundleDeletedFromDatabase(const std::string& bundleName);

    bool VerifyPermissionDeletedFromDatabase(AccessTokenID tokenId);

    bool VerifyTokenInCache(AccessTokenID tokenId);

    bool VerifyTokenNotInCache(AccessTokenID tokenId);

    bool VerifyBundleInCache(const std::string& bundleName, AccessTokenID tokenId);

    bool VerifyBundleNotInCache(const std::string& bundleName);

    bool VerifyPermissionDeletedFromKernel(AccessTokenID tokenId);

    bool VerifySpmDeletedFromKernel(AccessTokenID tokenId);

    void CleanTestData(const std::string& bundleName, int32_t userID = 100);

    void CleanAllTestData();
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // DELETE_IDENTITY_MOCK_TEST_H
