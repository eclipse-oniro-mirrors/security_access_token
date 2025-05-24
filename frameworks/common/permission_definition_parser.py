#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2025 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import json
import argparse
import os
import stat
import hashlib

PERMISSION_DEFINITION_PREFIX = '''
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_DEFINITION_PARSER_H
#define PERMISSION_DEFINITION_PARSER_H

#include "permission_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
'''

PERMISSION_DEFINITION_SUFFIX_1 = '''
};
'''

PERMISSION_DEFINITION_SUFFIX_2 = '''
const uint32_t MAX_PERM_SIZE = sizeof(g_permList) / sizeof(PermissionBriefDef);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_DEFINITION_PARSER_H
'''

PERMISSION_NAME_STRING = "char PERMISSION_NAME_%i[] = \"%s\";\n"

PERMISSION_LIST_DECLEARE = "const static PermissionBriefDef g_permList[] = {"

VERSION_STRING = "\nconst char* PERMISSION_DEFINITION_VERSION = \"%s\";"

PERMISSION_BRIEF_DEFINE_PATTERN = '''
{
    .permissionName = PERMISSION_NAME_%i,
    .grantMode = %s,
    .availableLevel = %s,
    .availableType = %s,
    .provisionEnable = %s,
    .distributedSceneEnable = %s,
    .isKernelEffect = %s,
    .hasValue = %s
},'''

JSON_VALUE_CONVERT_TO_CPP_DICT = {
    "user_grant": "USER_GRANT",
    "system_grant": "SYSTEM_GRANT",
    "normal": "APL_NORMAL",
    "system_basic": "APL_SYSTEM_BASIC",
    "system_core": "APL_SYSTEM_CORE",
}

CONVERT_TARGET_PLATFORM = {
    "phone": "phone",
    "watch": "wearable",
    "wearable": "wearable",
    "tablet": "tablet",
    "pc": "2in1",
    "tv": "tv",
    "car": "car",
}


class PermissionDef(object):
    def __init__(self, permission_def_dict, code):
        self.name = permission_def_dict["name"]
        self.grant_mode = JSON_VALUE_CONVERT_TO_CPP_DICT[
            permission_def_dict["grantMode"]]

        self.available_level = JSON_VALUE_CONVERT_TO_CPP_DICT[
            permission_def_dict["availableLevel"]
        ]
        self.available_type = permission_def_dict["availableType"]

        if "provisionEnable" in permission_def_dict and permission_def_dict["provisionEnable"]:
            self.provision_enable = "true"
        else:
            self.provision_enable = "false"

        if "distributedSceneEnable" in permission_def_dict and permission_def_dict["distributedSceneEnable"]:
            self.distributed_scene_enable = "true"
        else:
            self.distributed_scene_enable = "false"

        if "isKernelEffect" in permission_def_dict and permission_def_dict["isKernelEffect"]:
            self.is_kernel_effect = "true"
        else:
            self.is_kernel_effect = "false"

        if "hasValue" in permission_def_dict and permission_def_dict["hasValue"]:
            self.has_value = "true"
        else:
            self.has_value = "false"

        if permission_def_dict["since"] >= 20 and not "deviceTypes" in permission_def_dict:
            raise Exception("No deviceTypes in permission difinition of {}".format(self.name))

        if "deviceTypes" in permission_def_dict:
            if isinstance(permission_def_dict["deviceTypes"], list) and len(permission_def_dict["deviceTypes"]) > 0:
                self.device_types = permission_def_dict["deviceTypes"]
            else:
                raise Exception("Must be filled with available device type list, name = {}".format(self.name))
        else:
            self.device_types = ["general"]

        self.code = code

    def dump_permission_name(self):
        return PERMISSION_NAME_STRING % (
            self.code, self.name
        )

    def dump_struct(self):
        entry = PERMISSION_BRIEF_DEFINE_PATTERN % (
            self.code, self.grant_mode, self.available_level,
            self.available_type, self.provision_enable, self.distributed_scene_enable,
            self.is_kernel_effect, self.has_value
        )
        return entry

    def check_device_type(self, target_platform):
        if "general" in self.device_types:
            return True
        if target_platform in self.device_types:
            return True
        return False


def parse_json(path, platform):
    extend_perm = {
        'name' : 'ohos.permission.KERNEL_ATM_SELF_USE',
        'grantMode' : 'system_grant',
        'availableLevel' : 'system_core',
        'availableType' : 'SYSTEM',
        'since' : 18,
        'deprecated' : '',
        'provisionEnable' : True,
        'distributedSceneEnable' : True,
        'isKernelEffect' : True,
        'hasValue' : True
    }

    def_list = []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        index = 0
        for perm in data["definePermissions"]:
            perm_def = PermissionDef(perm, index)
            if not perm_def.check_device_type(platform):
                continue
            def_list.append(perm_def)
            index += 1
        def_list.append(PermissionDef(extend_perm, index))
    return def_list


def convert_to_cpp(path, permission_list, hash_str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, mode), "w") as f:
        f.write(PERMISSION_DEFINITION_PREFIX)
        for perm in permission_list:
            f.write(perm.dump_permission_name())
        f.write(PERMISSION_LIST_DECLEARE)
        for perm in permission_list:
            f.write(perm.dump_struct())
        f.write(PERMISSION_DEFINITION_SUFFIX_1)
        f.write(VERSION_STRING % (hash_str))
        f.write(PERMISSION_DEFINITION_SUFFIX_2)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-path', help='the output cpp path', required=True)
    parser.add_argument('--input-json', help='json file for permission difinition', required=True)
    parser.add_argument('--target-platform', help='build target platform', required=True)
    return parser.parse_args()


def get_file_hash(path):
    hash_object = hashlib.sha256()
    with open(path, 'rb') as f:
        while line := f.read(4096):
            hash_object.update(line)
    return hash_object.hexdigest()

if __name__ == "__main__":
    input_args = parse_args()
    curr_platform = "general"
    if input_args.target_platform in CONVERT_TARGET_PLATFORM:
        curr_platform = CONVERT_TARGET_PLATFORM[input_args.target_platform]
    permission_list = parse_json(input_args.input_json, curr_platform)
    hash_str = get_file_hash(input_args.input_json)
    convert_to_cpp(input_args.output_path, permission_list, hash_str)
