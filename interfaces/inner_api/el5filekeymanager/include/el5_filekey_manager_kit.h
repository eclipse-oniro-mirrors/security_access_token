/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef EL5_FILEKEY_MANAGER_KIT_H
#define EL5_FILEKEY_MANAGER_KIT_H

#include <string>

#include "data_lock_type.h"
#include "el5_filekey_callback_interface.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyManagerKit {
public:
    /**
     * @brief Acquire access of data.
     * If acquiring MEDIA_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA permission,
     * if acquiring ALL_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA permission.
     * @permission ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA or ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA
     * @param type Type of data accessed
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t AcquireAccess(DataLockType type);
    /**
     * @brief Release access of data.
     * If releasing MEDIA_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA permission,
     * if releasing ALL_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA permission.
     * @permission ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA or ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA
     * @param type Type of data accessed
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t ReleaseAccess(DataLockType type);
    /**
     * @brief Generate app key of the installed application.
     * @param uid The uid
     * @param bundleName bundle name
     * @param keyId Return keyId of the installed application
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId);
    /**
     * @brief Delete app key of the uninstalled application.
     * @param bundleName bundle name
     * @param userId The user id
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t DeleteAppKey(const std::string& bundleName, int32_t userId);
    /**
     * @brief Get key infos of the specified user, the state is unloaded.
     * @param userId The user id
     * @param keyInfos Key infos of the specified user id, as query result
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t GetUserAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos);
    /**
     * @brief Set app key load infos of the specified user.
     * @param userId The user id
     * @param loadInfos Key load infos of the specified user id
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t ChangeUserAppkeysLoadInfo(int32_t userId, std::vector<std::pair<std::string, bool>> &loadInfos);
    /**
     * @brief Set file path policy.
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t SetFilePathPolicy();
    /**
     * @brief Register app key generation callback.
     * @param callback smart point of class El5FilekeyCallbackInterface quote
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback);
    /**
     * @brief Get all key infos of the specified user.
     * @param userId The user id
     * @param keyInfos Key infos of the specified user id, as query result
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t GetUserAllAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos);
    /**
     * @brief Generate app key of the installed data group.
     * @param uid The uid
     * @param groupID ID of the data group
     * @param keyId Return keyId of the installed data group
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId);
    /**
     * @brief Delete app key of the uninstalled data group.
     * @param uid The uid
     * @param groupID ID of the data group
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t DeleteGroupIDKey(uint32_t uid, const std::string &groupID);
    /**
     * @brief Query specified type of app key's state.
     * If acquiring MEDIA_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA permission,
     * if acquiring ALL_DATA, you need to apply for ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA permission.
     * @permission ohos.permission.ACCESS_SCREEN_LOCK_MEDIA_DATA or ohos.permission.ACCESS_SCREEN_LOCK_ALL_DATA
     * @param type Type of data accessed
     * @return error code, see el5_filekey_manager_error.h
     */
    static int32_t QueryAppKeyState(DataLockType type);
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_KIT_H
