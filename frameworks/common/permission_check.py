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


REQUIRED_ATTRS = [
    "name",
    "grantMode",
    "availableLevel",
    "since",
    "provisionEnable",
    "distributedSceneEnable"
]


ATTRS_ONLY_IN_RESOURCE = [
    "label",
    "description"
]


def parse_definition_json(path):
    permission_maps = {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        for perm in data["definePermissions"]:
            permission_maps[perm["name"]] = perm
    return permission_maps


def parse_module_json(path):
    permission_maps = {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        for perm in data["module"]["definePermissions"]:
            permission_maps[perm["name"]] = perm
    return permission_maps


def check_required_param(defs, filename):
    for attr in REQUIRED_ATTRS:
        if not attr in defs:
            raise Exception("Not found {} of {} in {}".format(
                attr, defs["name"], filename))


def check_consistency(def_in_module, full_def):
    for attr, value in full_def.items():
        if not attr in def_in_module:
                continue
        if not value == def_in_module[attr]:
            raise Exception("{} of {} is inconsistent in module.json and permission_definition.json".format(
                attr, def_in_module["name"]))

    for attr in def_in_module.keys():
        if attr in ATTRS_ONLY_IN_RESOURCE:
            continue
        elif not attr in full_def:
            raise Exception("{} of {} should be define in permission_definition.json".format(attr,
                def_in_module["name"]))


def check_maps(module_map, definition_map):
    for name, perm_def in definition_map.items():
        if not "availableType" in perm_def:
            raise Exception("Cannot define permission {} without availableType " \
                "in permission_definition.json".format(name))
        if perm_def["availableType"] == "SERVICE":
            if name in module_map:
                raise Exception("Cannot define permission {} for SERVICE in module.json".format(name))
            continue
        if not name in module_map:
            raise Exception("To add permission definition of {} in system_global_resource.".format(name))
        check_required_param(module_map[name], "module.json")
        check_required_param(definition_map[name], "permission_definition.json")
        check_consistency(module_map[name], definition_map[name])


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root-dir', help='build root dir', required=True)
    parser.add_argument('--input-full-permissions', help='json file for permission definition', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    module_json_path = os.path.join("base/global/system_resources/systemres/main", "module.json")
    module_json_path = os.path.join(input_args.source_root_dir, module_json_path)
    module_map = parse_module_json(module_json_path)
    definition_map = parse_definition_json(input_args.input_full_permissions)
    check_maps(module_map, definition_map)
    print("Check permission consistency pass!")