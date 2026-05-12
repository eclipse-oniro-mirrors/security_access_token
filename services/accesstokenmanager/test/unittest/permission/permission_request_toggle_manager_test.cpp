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

#include "access_token.h"
#include "access_token_error.h"
#include "ipc_skeleton.h"
#include "permission_request_toggle_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t BASE_USER_RANGE = 200000;
}

class PermissionRequestToggleManagerTest : public testing::Test {};

HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = -1;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    userID = 123;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        "", status, userID));

    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    status = static_cast<uint32_t>(-1);
    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = 123;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));

    status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus003, TestSize.Level0)
{
    const int32_t resolvedUser = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t getStatus = PermissionRequestToggleStatus::OPEN;

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, 0));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, getStatus, resolvedUser));
    ASSERT_EQ(status, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, resolvedUser));
}

HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = -1;
    uint32_t status;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));

    userID = 123;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "", status, userID));

    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));

    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID));
}

HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = 123;
    uint32_t setStatusClose = PermissionRequestToggleStatus::CLOSED;
    uint32_t setStatusOpen = PermissionRequestToggleStatus::OPEN;
    uint32_t getStatus;

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));
    ASSERT_EQ(setStatusOpen, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", setStatusClose, userID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));
    ASSERT_EQ(setStatusClose, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", setStatusOpen, userID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.CAMERA", getStatus, userID));
    ASSERT_EQ(setStatusOpen, getStatus);
}

HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus003, TestSize.Level0)
{
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "ohos.permission.APP_TRACKING_CONSENT", status, 123));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus004, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t oriStatus = PermissionRequestToggleStatus::OPEN;
    uint32_t status = PermissionRequestToggleStatus::OPEN;

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, oriStatus, 0));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, 0));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, 0));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, oriStatus, 0));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
