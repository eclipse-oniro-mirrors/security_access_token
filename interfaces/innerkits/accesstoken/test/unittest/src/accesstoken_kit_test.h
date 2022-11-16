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

#ifndef ACCESSTOKEN_KIT_TEST_H
#define ACCESSTOKEN_KIT_TEST_H

#include <gtest/gtest.h>

#include "access_token.h"
#include "permission_def.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static const std::string TEST_PERMISSION_NAME_GAMMA = "ohos.permission.GAMMA";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static const int TEST_USER_ID = 0;
static const int TEST_USER_ID_INVALID = -1;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int INVALID_BUNDLENAME_LEN = 260;
static const int INVALID_APPIDDESC_LEN = 10244;
static const int INVALID_LABEL_LEN = 260;
static const int INVALID_DESCRIPTION_LEN = 260;
static const int INVALID_PERMNAME_LEN = 260;
static const int CYCLE_TIMES = 100;
static const int THREAD_NUM = 3;
static const int INVALID_DCAP_LEN = 1025;
static const int INVALID_DLP_TYPE = 4;
class AccessTokenKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    unsigned int GetAccessTokenID(int userID, std::string bundleName, int instIndex);
    void AllocHapToken(std::vector<PermissionDef>& permmissionDefs,
        std::vector<PermissionStateFull>& permissionStateFulls, int32_t apiVersion);
    void DeleteTestToken() const;
    void AllocTestToken() const;

    uint64_t selfTokenId_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_KIT_TEST_H
