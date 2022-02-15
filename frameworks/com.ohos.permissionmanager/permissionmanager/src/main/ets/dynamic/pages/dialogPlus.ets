/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

import { privacyDialog } from "../common/components/dialog.ets"
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';

@Entry
@Component
struct dialogPlusPage {
  @State count: number = 0
  @State result: Array<any> = []
  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: privacyDialog({ cancel: this.privacyCancel, confirm: this.privacyAccept, count:$count, result: $result }),
    cancel: this.privacyExist,
    autoCancel: true,
    alignment: DialogAlignment.Center
  })
  async privacyAccept(group, accessTokenId, permissionList, userFixedFlag) {
    var acManager = abilityAccessCtrl.createAtManager()
    group.permissions.forEach(async permission => {
      const result = await acManager.grantUserGrantedPermission(accessTokenId, permission, userFixedFlag)
      var index = permissionList.indexOf(permission)
      if (index == -1) {
        console.log("GrantAbility grant permission:" + permission)
      }else {
        if (result == 0) {
          this.result[index] = 0
          console.log("GrantAbility grant permission:" + permission)
        } else {
          console.log("GrantAbility failed to grant permission:" + permission + " ret:" + result)
        }
      }
    })
    this.count ++
  }
  async privacyCancel(group, accessTokenId, permissionList, userFixedFlag) {
    var acManager = abilityAccessCtrl.createAtManager()
    group.permissions.forEach(async permission => {
      const result = await acManager.revokeUserGrantedPermission(accessTokenId, permission, userFixedFlag)
      var index = permissionList.indexOf(permission)
      if (index != -1 && result == 0) {
        this.result[index] = -1
        console.log("GrantAbility revoke permission:" + permission)
      }
    })
    this.count ++
  }
  privacyExist() {
    console.info("exist")
  }
  aboutToAppear() {
    this.privacyDialogController.open()
  }
  build() {
  }
}

