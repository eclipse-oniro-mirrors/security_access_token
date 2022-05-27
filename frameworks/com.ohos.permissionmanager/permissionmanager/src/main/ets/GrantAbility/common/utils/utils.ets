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
import { permissionGroups, groups } from "../model/permissionGroup.ets"

const TAG = 'PermissionManager_Log';

export function getPermissionGroup(permission: string) {
  for (var i = 0; i < permissionGroups.length; i++) {
    if (permissionGroups[i].permissionName == permission) {
      if(permissionGroups[i].groupName == 'OTHER') {
        return {
          "name": permissionGroups[i].groupName,
          "groupName": permissionGroups[i].groupName,
          "label": permissionGroups[i].label,
          "icon": permissionGroups[i].icon,
          "description": "",
          "permissions": [
            permissionGroups[i].permissionName
          ]
        }
      }else {
        return groups[permissionGroups[i].groupId]
      }
    }
  }
}

export class Log {
  static info(log) {
    console.info(`Info: ${TAG}  ${log}`)
  }

  static error(log) {
    console.info(`Error: ${TAG}  ${log}`)
  }
}