#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2026 Huawei Device Co., Ltd.
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

import argparse
import json
import os
import stat


HEADER_PREFIX = '''/*
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

#ifndef CLI_PERMISISON_MAP_H
#define CLI_PERMISISON_MAP_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace AccessToken {

'''

HEADER_SUFFIX = '''
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // CLI_PERMISISON_MAP_H
'''

CLI_PERMISSION_KEYS = ("cliPermission", "cli_permission")
USED_PERMISSIONS_KEYS = ("usedPermissions", "used_permissions")


class CliPermissionMapping(object):
    def __init__(self, cli_permission, permission_list, index):
        self.cli_permission = cli_permission
        self.permission_list = permission_list
        self.index = index

    @staticmethod
    def _dump_cpp_string(value):
        return json.dumps(value, ensure_ascii=False)

    def dump_map_entry(self):
        lines = [
            "    {\n",
            "        %s,\n" % self._dump_cpp_string(self.cli_permission),
            "        {\n",
        ]
        for permission in self.permission_list:
            lines.append("            %s,\n" % self._dump_cpp_string(permission))
        lines.extend([
            "        }\n",
            "    },\n",
        ])
        return "".join(lines)


def get_required_value(item, keys, index):
    for key in keys:
        if key in item:
            return item[key]
    raise Exception("No {} in mappings[{}].".format("/".join(keys), index))


def parse_json(path):
    with open(path, "r", encoding="utf-8") as json_file:
        data = json.load(json_file)
    if not isinstance(data, dict):
        raise Exception("Cli permission map must be a json object.")

    mappings = data.get("mappings")
    if not isinstance(mappings, list):
        raise Exception("mappings must be a list.")

    cli_permission_set = set()
    result = []
    for index, item in enumerate(mappings):
        if not isinstance(item, dict):
            raise Exception("mappings[{}] must be a json object.".format(index))

        cli_permission = get_required_value(item, CLI_PERMISSION_KEYS, index)
        if not isinstance(cli_permission, str) or not cli_permission:
            raise Exception("cliPermission in mappings[{}] must be a non-empty string.".format(index))
        if cli_permission in cli_permission_set:
            raise Exception("Duplicate cliPermission {}.".format(cli_permission))
        cli_permission_set.add(cli_permission)

        permission_list = get_required_value(item, USED_PERMISSIONS_KEYS, index)
        if not isinstance(permission_list, list) or not permission_list:
            raise Exception("usedPermissions in mappings[{}] must be a non-empty list.".format(index))
        permission_set = set()
        for permission in permission_list:
            if not isinstance(permission, str) or not permission:
                raise Exception(
                    "usedPermissions in mappings[{}] must only contain non-empty strings.".format(index))
            if permission in permission_set:
                raise Exception("Duplicate permission {} in mappings[{}].".format(permission, index))
            permission_set.add(permission)

        result.append(CliPermissionMapping(cli_permission, permission_list, index))
    return result


def convert_to_cpp(path, mapping_list):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, mode), "w", encoding="utf-8") as output_file:
        output_file.write(HEADER_PREFIX)
        output_file.write("const static std::map<std::string, std::vector<std::string>> g_cliPermissionMap = {\n")
        for mapping in mapping_list:
            output_file.write(mapping.dump_map_entry())
        output_file.write("};\n")
        output_file.write(HEADER_SUFFIX)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-path", help="the output header path", required=True)
    parser.add_argument("--input-json", help="json file for cli permission mapping", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    cli_permission_list = parse_json(input_args.input_json)
    convert_to_cpp(input_args.output_path, cli_permission_list)
