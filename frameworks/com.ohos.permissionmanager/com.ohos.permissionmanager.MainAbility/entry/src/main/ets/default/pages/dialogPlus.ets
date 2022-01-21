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
import { dialogData } from "../common/model/dialogDataList.ets"
import { permissionGroups, groups } from "../common/model/permissionGroup.ets"
import bundle from '@ohos.bundle';
import prompt from '@system.prompt';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';

@Entry
@Component
struct dialogPlusPage {
  @State count: number = 0
  @State userId: number = 0
  @State GET_BUNDLE_DEFAULT: number = 0x00000000
  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: privacyDialog({ cancel: this.privacyCancel, confirm: this.privacyAccept, count:this.count }),
    cancel: this.privacyExist,
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0 , dy: -12 },
    customStyle: true
  })
  privacyAccept() {
      bundle.getApplicationInfo('com.example.myapplication', this.GET_BUNDLE_DEFAULT, this.userId).then(async res => {
        var acManager = abilityAccessCtrl.createAtManager()
        var verify = await acManager.verifyAccessToken(res.accessTokenId, res.permissions[this.count])
        if(verify) {
          var permission = permissionGroups.filter(item => item.name == res.permissions[this.count])
          if(permission.length) {
            var group = groups.filter(item => item.name == permission[0].group)
            await group[0].permissions.forEach(async item => {
              var permissionFlag = await acManager.getPermissionFlags(res.accessTokenId, item)
              acManager.grantUserGrantedPermission(res.accessTokenId, item, permissionFlag).then(result => {
                if(result !== 0) {
                  prompt.showToast({
                    message: '授权信息失败',
                    duration: 2000,
                  });
                }
              })
            })
            this.verify(res.accessTokenId, res.permissions[this.count])
          }else {
            var permissionFlag = await acManager.getPermissionFlags(res.accessTokenId, res.permissions[this.count])
            acManager.grantUserGrantedPermission(res.accessTokenId, res.permissions[this.count], permissionFlag).then(result => {
              if(result !== 0) {
                prompt.showToast({
                  message: '授权信息失败',
                  duration: 2000,
                });
              }
              this.verify(res.accessTokenId, res.permissions[this.count])
            })
          }
        }else {
            this.verify(res.accessTokenId, res.permissions[this.count])
        }
      }).catch(() => {
        this.count < dialogData.length ? this.count += 1 : ''
      })

  }
  privacyCancel() {
    bundle.getApplicationInfo('com.example.myapplication', this.GET_BUNDLE_DEFAULT, this.userId).then(async res => {
      var acManager = abilityAccessCtrl.createAtManager()
      var verify = await acManager.verifyAccessToken(res.accessTokenId, res.permissions[this.count])
      if(verify) {
        var permission = permissionGroups.filter(item => item.name == res.permissions[this.count])
        if(permission.length) {
          var group = groups.filter(item => item.name == permission[0].group)
          await group[0].permissions.forEach(async item => {
            var permissionFlag = await acManager.getPermissionFlags(res.accessTokenId, item)
            acManager.revokeUserGrantedPermission(res.accessTokenId, item, permissionFlag).then(result => {
              if(result !== 0) {
                prompt.showToast({
                  message: '授权信息失败',
                  duration: 2000,
                });
              }
            })
          })
          this.verify(res.accessTokenId, res.permissions[this.count])
        }else {
          var permissionFlag = await acManager.getPermissionFlags(res.accessTokenId, res.permissions[this.count])
          acManager.revokeUserGrantedPermission(res.accessTokenId, res.permissions[this.count], permissionFlag).then(result => {
            if(result !== 0) {
              prompt.showToast({
                message: '授权信息失败',
                duration: 2000,
              });
            }
            this.verify(res.accessTokenId, res.permissions[this.count])
          })
        }
      }else {
        this.verify(res.accessTokenId, res.permissions[this.count])
      }
    }).catch(() => {
      this.count < dialogData.length ? this.count += 1 : ''
    })

  }
  async verify(tokenId, permissions) {
    if(this.count < dialogData.length) {
      this.count += 1
      var acManager = abilityAccessCtrl.createAtManager()
      var verify = await acManager.verifyAccessToken(tokenId, permissions)
      if (verify) {
        this.verify(tokenId, permissions)
      }
    }
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
