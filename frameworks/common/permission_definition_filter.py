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


def filter_permission_json(path, output):
    new_def_list = []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        index = 0
        for perm in data["definePermissions"]:
            if not "availableType" in perm:
                print("[ERROR] No availableType in permission definition")
                raise Exception(-1)
            if perm["availableType"] == "SERVICE":
                continue
            new_def_list.append(perm)
        data["definePermissions"] = new_def_list
        dirpath = os.path.dirname(output)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        with open(output, "w", encoding="utf-8") as fout:
            json.dump(data, fout, indent=4)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-path', help='the output cpp path', required=True)
    parser.add_argument('--input-json', help='json file for filtered permission definition', required=True)
    return parser.parse_args()

if __name__ == "__main__":
    input_args = parse_args()
    filter_permission_json(input_args.input_json, input_args.output_path)
