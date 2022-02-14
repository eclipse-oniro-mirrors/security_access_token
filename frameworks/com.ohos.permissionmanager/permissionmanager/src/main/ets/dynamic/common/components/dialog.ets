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

import { getPermissionGroup } from '../utils/utils.ets'
import { BundleFlag, userId } from '../model/bundle.ets'
import Constants from '../utils/constant.ets'
import featureAbility from '@ohos.ability.featureAbility'
import abilityAccessCtrl from '@ohos.abilityAccessCtrl'
import bundle from '@ohos.bundle'
import Resmgr from '@ohos.resourceManager'

@Extend(Button) function customizeButton() {
  .backgroundColor($r('app.color.default_background_color'))
  .fontColor($r('app.color.button_color'))
}

@CustomDialog
export struct privacyDialog {
  @Link count: number
  @Link result: Array<number>
  controller: CustomDialogController
  cancel: (group, accessTokenId, permissionList, userFixedFlag) => void
  confirm: (group, accessTokenId, permissionList, userFixedFlag) => void
  @State accessTokenId: number = 0
  @State hasPrepared: boolean = false
  @State reqPerms: Array<string> = []
  @State grantGroups: Array<any> = []
  @State userFixedFlag: number = 2 // means user fixed
  @State appName: string = ""

  build() {
    Column() {
      if (this.hasPrepared && this.verify(this.reqPerms[this.count])) {
        Image(this.grantGroups[this.count].icon)
          .width(Constants.DIALOG_ICON_WIDTH)
          .height(Constants.DIALOG_ICON_HEIGHT)
          .margin({
            top: Constants.DIALOG_ICON_MARGIN_TOP
          })
        Text(`${this.count + 1} / ${this.reqPerms.length}`)
          .fontSize(Constants.DIALOG_LABEL_FONT_SIZE)
          .fontColor($r('app.color.secondary_font_color'))
          .margin({
            top: Constants.DIALOG_LABEL_MARGIN_TOP
          })
        Column() {
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("是否允许" + this.appName + "访问" +
                this.grantGroups[this.count].groupName).fontSize(Constants.DIALOG_REQ_FONT_SIZE)
                .margin({
                  top: Constants.DIALOG_REQ_MARGIN_TOP,
                  left: Constants.DIALOG_REQ_MARGIN_LEFT
                })
            }
          }
          Row() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text("用于" + this.grantGroups[this.count].description).fontSize(Constants.DIALOG_DESP_FONT_SIZE)
                .fontColor($r('app.color.secondary_font_color'))
                .margin({
                  top: Constants.DIALOG_DESP_MARGIN_TOP,
                  left: Constants.DIALOG_DESP_MARGIN_LEFT
                })
            }
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.SpaceAround }) {
          Button('禁止')
            .fontSize(Constants.BUTTON_FONT_SIZE)
            .onClick(() => {
              this.cancel(this.grantGroups[this.count], this.accessTokenId, this.reqPerms, this.userFixedFlag)
              if (this.count === this.reqPerms.length) {
                this.controller.close()
              }
            }).customizeButton()
          Text('|').fontSize(Constants.BUTTON_DIVIDER_FONT_SIZE).fontColor($r('app.color.divider_color'))
          Button('允许')
            .fontSize(Constants.BUTTON_FONT_SIZE)
            .onClick(() => {
              this.confirm(this.grantGroups[this.count], this.accessTokenId, this.reqPerms, this.userFixedFlag)
              if (this.count === this.reqPerms.length) {
                this.controller.close()
              }
            }).customizeButton()
        }.margin({
          top: Constants.BUTTON_MARGIN_TOP
        })
      }
    }
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(Constants.DIALOG_BORDER_RADIUS)
    .height(Constants.DIALOG_HEIGHT)
    .width(Constants.DIALOG_WIDTH)
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
    this.hasPrepared = false;
    featureAbility.getWant((err, want) => {
      this.reqPerms = want.parameters['ohos.user.grant.permission']
      this.accessTokenId = want.parameters['ohos.aafwk.param.callerToken']
      console.log("GrantAbility request permission=" + JSON.stringify(this.reqPerms) + " tokenId = " + this.accessTokenId)
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
      bundle.getNameForUid(want.parameters['ohos.aafwk.param.callerUid'], (err, data) => {
        if(err) {
          console.log("GrantAbility getNameForUid error :" + err)
          return
        }
        console.log("GrantAbility getNameForUid data :" + data)
        bundle.getApplicationInfo(data, BundleFlag.GET_BUNDLE_DEFAULT, userId).then(applicationInfo => {
          console.log("GrantAbility applicationInfo :" + JSON.stringify(applicationInfo))
          Resmgr.getResourceManager(data).then(item => {
            item.getString(applicationInfo.labelId, (err, value) => {
              if (value == undefined) {
                console.log("GrantAbility label :" )
                this.appName = applicationInfo.label.replace('$string:', '')
              } else {
                console.log("GrantAbility labelValue :" + value)
                this.appName = value
              }
            })
          })
        }).catch(err => {
          console.log("GrantAbility applicationInfo11 error :" + err)
        })
      })
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
