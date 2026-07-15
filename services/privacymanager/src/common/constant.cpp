/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "constant.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::map<std::string, int32_t> Constant::PERMISSION_OPCODE_MAP = {
    std::map<std::string, int32_t>::value_type("ohos.permission.ANSWER_CALL", Constant::OP_ANSWER_CALL),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CALENDAR", Constant::OP_READ_CALENDAR),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CALL_LOG", Constant::OP_READ_CALL_LOG),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CELL_MESSAGES", Constant::OP_READ_CELL_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_CONTACTS", Constant::OP_READ_CONTACTS),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_MESSAGES", Constant::OP_READ_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.RECEIVE_MMS", Constant::OP_RECEIVE_MMS),
    std::map<std::string, int32_t>::value_type("ohos.permission.RECEIVE_SMS", Constant::OP_RECEIVE_SMS),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.RECEIVE_WAP_MESSAGES", Constant::OP_RECEIVE_WAP_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.MICROPHONE", Constant::OP_MICROPHONE),
    std::map<std::string, int32_t>::value_type("ohos.permission.SEND_MESSAGES", Constant::OP_SEND_MESSAGES),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CALENDAR", Constant::OP_WRITE_CALENDAR),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CALL_LOG", Constant::OP_WRITE_CALL_LOG),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_CONTACTS", Constant::OP_WRITE_CONTACTS),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.DISTRIBUTED_DATASYNC", Constant::OP_DISTRIBUTED_DATASYNC),
    std::map<std::string, int32_t>::value_type("ohos.permission.MANAGE_VOICEMAIL", Constant::OP_MANAGE_VOICEMAIL),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.LOCATION_IN_BACKGROUND", Constant::OP_LOCATION_IN_BACKGROUND),
    std::map<std::string, int32_t>::value_type("ohos.permission.LOCATION", Constant::OP_LOCATION),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.APPROXIMATELY_LOCATION", Constant::OP_APPROXIMATELY_LOCATION),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.CONTROL_LOCATION_SWITCH", Constant::OP_CLI_CONTROL_LOCATION_SWITCH),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.SET_HOTSPOT", Constant::OP_CLI_SET_HOTSPOT),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.GET_HOTSPOT", Constant::OP_CLI_GET_HOTSPOT),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.MANAGE_WIFI_TOGGLE", Constant::OP_CLI_MANAGE_WIFI_TOGGLE),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.MANAGE_WIFI_SCAN", Constant::OP_CLI_MANAGE_WIFI_SCAN),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.cli.MANAGE_WIFI_CONNECT", Constant::OP_CLI_MANAGE_WIFI_CONNECT),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.MANAGE_NFC_SWITCH",
        Constant::OP_CLI_NFC_SWITCH),
    std::map<std::string, int32_t>::value_type("ohos.permission.MEDIA_LOCATION", Constant::OP_MEDIA_LOCATION),
    std::map<std::string, int32_t>::value_type("ohos.permission.CAMERA", Constant::OP_CAMERA),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_MEDIA", Constant::OP_READ_MEDIA),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_MEDIA", Constant::OP_WRITE_MEDIA),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACTIVITY_MOTION", Constant::OP_ACTIVITY_MOTION),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_HEALTH_DATA", Constant::OP_READ_HEALTH_DATA),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_IMAGEVIDEO", Constant::OP_READ_IMAGEVIDEO),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_AUDIO", Constant::OP_READ_AUDIO),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_DOCUMENT", Constant::OP_READ_DOCUMENT),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_IMAGEVIDEO", Constant::OP_WRITE_IMAGEVIDEO),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_AUDIO", Constant::OP_WRITE_AUDIO),
    std::map<std::string, int32_t>::value_type("ohos.permission.WRITE_DOCUMENT", Constant::OP_WRITE_DOCUMENT),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WHOLE_CALENDAR", Constant::OP_READ_WHOLE_CALENDAR),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.WRITE_WHOLE_CALENDAR", Constant::OP_WRITE_WHOLE_CALENDAR),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.APP_TRACKING_CONSENT", Constant::OP_APP_TRACKING_CONSENT),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.GET_INSTALLED_BUNDLE_LIST", Constant::OP_GET_INSTALLED_BUNDLE_LIST),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACCESS_BLUETOOTH", Constant::OP_ACCESS_BLUETOOTH),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_PASTEBOARD", Constant::OP_READ_PASTEBOARD),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY", Constant::OP_READ_WRITE_DOWNLOAD_DIRECTORY),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY", Constant::OP_READ_WRITE_DOCUMENTS_DIRECTORY),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.READ_WRITE_DESKTOP_DIRECTORY", Constant::OP_READ_WRITE_DESKTOP_DIRECTORY),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.ACCESS_NEARLINK", Constant::OP_ACCESS_NEARLINK),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.CAPTURE_SCREEN", Constant::OP_CAPTURE_SCREEN),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO", Constant::SHORT_TERM_WRITE_IMAGEVIDEO),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.CAMERA_BACKGROUND", Constant::CAMERA_BACKGROUND),
    std::map<std::string, int32_t>::value_type(
        "ohos.permission.CUSTOM_SCREEN_CAPTURE", Constant::OP_CUSTOM_SCREEN_CAPTURE),
    std::map<std::string, int32_t>::value_type("ohos.permission.HOOK_KEY_EVENT", Constant::OP_HOOK_KEY_EVENT),
    std::map<std::string, int32_t>::value_type("ohos.permission.CONTROL_DEVICE", Constant::OP_CONTROL_DEVICE),
    std::map<std::string, int32_t>::value_type("ohos.permission.FLOAT_VIEW", Constant::OP_FLOAT_VIEW),
    std::map<std::string, int32_t>::value_type("ohos.permission.AGENT_FILE_ACCESS", Constant::OP_AGENT_FILE_ACCESS),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY_MEDIA_READ",
        Constant::OP_READ_WRITE_DOWNLOAD_DIRECTORY_MEDIA_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY_MEDIA_WRITE",
        Constant::OP_READ_WRITE_DOWNLOAD_DIRECTORY_MEDIA_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY_OTHER_READ",
        Constant::OP_READ_WRITE_DOWNLOAD_DIRECTORY_OTHER_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY_OTHER_WRITE",
        Constant::OP_READ_WRITE_DOWNLOAD_DIRECTORY_OTHER_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY_MEDIA_READ",
        Constant::OP_READ_WRITE_DOCUMENTS_DIRECTORY_MEDIA_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY_MEDIA_WRITE",
        Constant::OP_READ_WRITE_DOCUMENTS_DIRECTORY_MEDIA_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY_OTHER_READ",
        Constant::OP_READ_WRITE_DOCUMENTS_DIRECTORY_OTHER_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DOCUMENTS_DIRECTORY_OTHER_WRITE",
        Constant::OP_READ_WRITE_DOCUMENTS_DIRECTORY_OTHER_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DESKTOP_DIRECTORY_MEDIA_READ",
        Constant::OP_READ_WRITE_DESKTOP_DIRECTORY_MEDIA_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACCESS_USER_FULL_DISK",
        Constant::OP_ACCESS_USER_FULL_DISK),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DESKTOP_DIRECTORY_MEDIA_WRITE",
        Constant::OP_READ_WRITE_DESKTOP_DIRECTORY_MEDIA_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DESKTOP_DIRECTORY_OTHER_READ",
        Constant::OP_READ_WRITE_DESKTOP_DIRECTORY_OTHER_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.READ_WRITE_DESKTOP_DIRECTORY_OTHER_WRITE",
        Constant::OP_READ_WRITE_DESKTOP_DIRECTORY_OTHER_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.CUSTOM_SCREEN_RECORDING",
        Constant::OP_CUSTOM_SCREEN_RECORDING),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACCESS_USER_FULL_DISK_READ",
        Constant::OP_ACCESS_USER_FULL_DISK_READ),
    std::map<std::string, int32_t>::value_type("ohos.permission.ACCESS_USER_FULL_DISK_WRITE",
        Constant::OP_ACCESS_USER_FULL_DISK_WRITE),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.BUNDLE_ACTIVE_INFO",
        Constant::OP_CLI_BUNDLE_ACTIVE_INFO),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.WRITE_ACCESSIBILITY_CONFIG_VISION",
        Constant::OP_CLI_WRITE_ACCESSIBILITY_CONFIG_VISION),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.WRITE_ACCESSIBILITY_CONFIG_HEARING",
        Constant::OP_CLI_WRITE_ACCESSIBILITY_CONFIG_HEARING),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.WRITE_ACCESSIBILITY_CONFIG_ACTION",
        Constant::OP_CLI_WRITE_ACCESSIBILITY_CONFIG_ACTION),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.UNINSTALL_BUNDLE",
        Constant::OP_CLI_UNINSTALL_BUNDLE),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.GET_BUNDLE_INFO_PRIVILEGED",
        Constant::OP_CLI_GET_BUNDLE_INFO_PRIVILEGED),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.REMOVE_BUNDLE_DATA_AND_CACHE_FILES",
        Constant::OP_CLI_REMOVE_BUNDLE_DATA_AND_CACHE_FILES),
    std::map<std::string, int32_t>::value_type("ohos.permission.cli.MANAGE_DISPOSED_APP_STATUS",
        Constant::OP_CLI_MANAGE_DISPOSED_APP_STATUS),
};

bool Constant::TransferPermissionToOpcode(const std::string& permissionName, int32_t& opCode)
{
    if (PERMISSION_OPCODE_MAP.count(permissionName) == 0) {
        return false;
    }
    opCode = PERMISSION_OPCODE_MAP.at(permissionName);
    return true;
}

bool Constant::TransferOpcodeToPermission(int32_t opCode, std::string& permissionName)
{
    auto iter = std::find_if(PERMISSION_OPCODE_MAP.begin(), PERMISSION_OPCODE_MAP.end(),
        [opCode](const std::map<std::string, int32_t>::value_type item) {
            return item.second == opCode;
        });
    if (iter == PERMISSION_OPCODE_MAP.end()) {
        return false;
    }
    permissionName = iter->first;
    return true;
}

bool Constant::IsPrivacyPermission(const std::string& permissionName)
{
    return PERMISSION_OPCODE_MAP.count(permissionName) != 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
