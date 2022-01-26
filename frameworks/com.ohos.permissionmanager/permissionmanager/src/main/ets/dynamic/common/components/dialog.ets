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

import { getPermissionGroup } from "../utils/utils.ets"
import { BundleFlag, userId } from "../model/bundle.ets"
import bundle from '@ohos.bundle';
import featureAbility from '@ohos.ability.featureAbility';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';

@Extend(Button) function customizeButton() {
  .backgroundColor($r('app.color.default_background_color'))
  .fontColor($r('app.color.button_color'))
}

@CustomDialog
export struct privacyDialog {
  @Link count: number
  @Link result: Array<any>
  controller: CustomDialogController
  cancel: (group, accessTokenId, permissionList, userFixedFlag) => void
  confirm: (group, accessTokenId, permissionList, userFixedFlag) => void
  @State accessTokenId: number = 0
  @State hasPrepared: boolean = false
  @State reqPerms: Array<any> = []
  @State grantGroups: Array<any> = []
  @State userFixedFlag: number = 2 // means user fixed

  build() {
    Column() {
      if (this.hasPrepared && this.verify(this.reqPerms[this.count])) {
        Image(this.grantGroups[this.count].icon)
          .width(24)
          .height(24)
          .margin({
            top: 24
          })
        Text(`${this.count + 1} / ${this.reqPerms.length}`)
          .fontSize(14)
          .fontColor($r('app.color.secondary_font_color'))
          .margin({
            top: 2
          })
        Column() {
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("是否允许该应用访问" + this.grantGroups[this.count].groupName).fontSize(16)
                .margin({
                  top: 16,
                  left: 24
                })
            }
          }
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("用于" + this.grantGroups[this.count].description).fontSize(14)
                .fontColor($r('app.color.secondary_font_color'))
                .margin({
                  top: 2,
                  left: 24
                })
            }
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.SpaceAround }) {
          Button('禁止')
            .fontSize(16)
            .onClick(() => {
              this.cancel(this.grantGroups[this.count], this.accessTokenId, this.reqPerms, this.userFixedFlag)
              if (this.count === this.reqPerms.length) {
                this.controller.close()
              }
            }).customizeButton()
          Text('|').fontSize(30).fontColor($r('app.color.divider_color'))
          Button('允许')
            .fontSize(16)
            .onClick(() => {
              this.confirm(this.grantGroups[this.count], this.accessTokenId, this.reqPerms, this.userFixedFlag)
              if (this.count === this.reqPerms.length) {
                this.controller.close()
              }
            }).customizeButton()
        }.margin({
          top: 8
        })
      }
    }
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(24)
    .height(186)
    .width(336)
  }
  async verify(permission) {
    if(this.count >= this.grantGroups.length) {
      this.controller.close()
      this.aboutToDisappear()
      return false
    }
    if(this.grantGroups[this.count] == 0) {
      this.result[this.count] = -1
      this.count ++
      return false
    }
    var acManager = abilityAccessCtrl.createAtManager()
    var ret = await acManager.verifyAccessToken(this.accessTokenId, permission)
    if(ret == 0) {
      console.log("GrantAbility permission has already been granted:" + permission)
      this.result[this.count] = 0
      this.count ++
      return false
    }
    this.result[this.count] = -1
    return true
  }

  aboutToAppear() {
    this.count = 0;
    featureAbility.getWant((err, want) => {
      this.reqPerms = want.parameters["ohos.user.grant.permission"]
      console.log("GrantAbility request permission=" + JSON.stringify(this.reqPerms) + " bundleName=" + want.bundleName)
      bundle.getApplicationInfo(want.bundleName, BundleFlag.GET_BUNDLE_DEFAULT, userId).then(res => {
        this.accessTokenId = res.accessTokenId
      })
      this.reqPerms.forEach(item => {
        var group = getPermissionGroup(item)
        if(!group) {
          this.grantGroups.push(0)
          console.log("GrantAbility permission not find:" + item)
        }else {
          this.grantGroups.push(group)
        }
      })
      this.hasPrepared = true;
    })
  }

  aboutToDisappear() {
    console.log("GrantAbility result=" + JSON.stringify(this.result))
    featureAbility.terminateSelfWithResult({
      resultCode: 1,
      want: {
        parameters: {
          "ohos.user.grant.permission": this.reqPerms,
          "ohos.user.grant.permission.result": this.result
        }
      }
    })
  }
}
