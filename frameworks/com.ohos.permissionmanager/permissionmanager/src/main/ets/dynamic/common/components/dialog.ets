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
import { BundleFlag, USER_ID } from '../model/bundle.ets'
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
  @State initStatus: number = Constants.INIT_NEED_TO_WAIT
  @State reqPerms: Array<string> = []
  @State grantGroups: Array<any> = []
  @State userFixedFlag: number = 2 // means user fixed
  @State appName: string = ""

  build() {
    Column() {
      if ((this.initStatus != Constants.INIT_NEED_TO_WAIT) && this.verify(this.reqPerms[this.count])) {
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
                .fontColor($r('app.color.secondary_font_color'))
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
    if((this.initStatus == Constants.INIT_NEED_TO_TERMINATED) || (this.count >= this.grantGroups.length)) {
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
    var flag = await acManager.getPermissionFlags(this.accessTokenId, permission)
    if(flag == this.userFixedFlag) {
      console.log("GrantAbility permission has been fixed:" + permission)
      this.result[this.count] = 0
      this.count ++
      return false
    }
    this.result[this.count] = -1
    return true
  }

  getApplicationName(uid) {
    bundle.getNameForUid(uid).then((data) => {
      console.log("GrantAbility getApplicationName bundleName:" + data)
      bundle.getApplicationInfo(data, BundleFlag.GET_BUNDLE_DEFAULT, USER_ID).then(applicationInfo => {
        Resmgr.getResourceManager(data).then(item => {
          item.getString(applicationInfo.labelId, (err, value) => {
            if (value == undefined) {
              this.appName = applicationInfo.label
            } else {
              this.appName = value
            }
            console.log("GrantAbility hap label:" + applicationInfo.label + ", value:"+this.appName)
          })
        })
      }).catch(err => {
        console.log("GrantAbility applicationInfo error :" + err)
        this.initStatus = Constants.INIT_NEED_TO_TERMINATED
      })
    }).catch(err => {
      console.log("GrantAbility getNameForUid error :" + JSON.stringify(err))
      this.initStatus = Constants.INIT_NEED_TO_TERMINATED
    })
  }

  aboutToAppear() {
    this.count = 0;
    this.initStatus = Constants.INIT_NEED_TO_WAIT
    this.result = []
    featureAbility.getWant((err, want) => {
      if (err.code != 0) {
        console.log("GrantAbility featureAbility.getWant err:" + err)
        this.initStatus = Constants.INIT_NEED_TO_TERMINATED
        return
      }
      this.reqPerms = want.parameters['ohos.user.grant.permission']
      this.accessTokenId = want.parameters['ohos.aafwk.param.callerToken']
      if (this.reqPerms == undefined || this.accessTokenId == undefined || this.reqPerms.length == 0) {
        console.log("GrantAbility invalid parameters")
        this.initStatus = Constants.INIT_NEED_TO_TERMINATED
        return
      }
      console.log("GrantAbility request permission=" + JSON.stringify(this.reqPerms) + ", tokenId = " + this.accessTokenId)
      this.reqPerms.forEach(item => {
        var group = getPermissionGroup(item)
        if(!group) {
          this.grantGroups.push(0)
          console.log("GrantAbility permission not find:" + item)
        }else {
          this.grantGroups.push(group)
        }
      })
      this.initStatus = Constants.INIT_NEED_TO_VERIFY
      this.getApplicationName(want.parameters['ohos.aafwk.param.callerUid'])
    })
  }

  aboutToDisappear() {
    var ret: number = Constants.RESULT_SUCCESS
    if (this.initStatus == Constants.INIT_NEED_TO_TERMINATED) {
      ret = Constants.RESULT_FAILURE
    }
    console.log("GrantAbility code:" + ret + ", result=" + JSON.stringify(this.result))
    featureAbility.terminateSelfWithResult({
      resultCode: ret,
      want: {
        parameters: {
          "ohos.user.grant.permission": this.reqPerms,
          "ohos.user.grant.permission.result": this.result
        }
      }
    })
  }
}
