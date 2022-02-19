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

import { backBar } from "../common/components/backBar.ets";
import router from '@system.router';
import bundle from "@ohos.bundle";
import { getAppLabel, getAppIcon } from "../common/utils/utils";
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import { authorizeDialog } from "../common/components/dialog.ets";
import { permissionDescriptions } from "../common/model/permissionGroup.ets";
import Constants from '../common/utils/constant.ets';

let routerData = router.getParams().routerData; // Routing jump data
let backTitle = router.getParams().backTitle; // return title name
let status = router.getParams().status; // Status: Allowed, Forbidden
let permission = router.getParams().permission; // permission name
class MeidaDocObj {
  name: string
  index: number
  groupName: string
  accessTokenId: string
  permission: string
  constructor(
    name: string,
    index: number,
    groupName: string,
    accessTokenId: string,
    permission: string
  ) {
    this.name = name
    this.index = index
    this.groupName = groupName
    this.accessTokenId = accessTokenId
    this.permission = permission
  }
}; // permission information class
class MediaListObj {
  labelId: string
  iconId: string
  versionName: string
  description: string
  constructor(
    labelId: string,
    iconId: string,
    versionName: string,
    description: string
  ) {
    this.labelId = labelId
    this.iconId = iconId
    this.versionName = versionName
    this.description = description
  }
}; // Permission application information class

@Entry
@Component
struct mediaDocumentPage {
  build() {
    Column() {
      GridContainer({ gutter: Constants.GUTTER }) {
        Row() {
          Row()
            .useSizeType({
              xs: { span: Constants.LEFT_XS_SPAN, offset: Constants.LEFT_XS_OFFSET },
              sm: { span: Constants.LEFT_SM_SPAN, offset: Constants.LEFT_SM_OFFSET },
              md: { span: Constants.LEFT_MD_SPAN, offset: Constants.LEFT_MD_OFFSET },
              lg: { span: Constants.LEFT_LG_SPAN, offset: Constants.LEFT_LG_OFFSET }
            })
            .height(Constants.FULL_HEIGHT)
            .backgroundColor(Color.White)
          Row() {
            Column() {
              Row() {
                backBar({ title: JSON.stringify(backTitle) })
              }
              Row() {
                Column() {
                  mediaDocumentItem()
                }.width(Constants.FULL_WIDTH)
              }
              .layoutWeight(Constants.LAYOUT_WEIGHT)
            }
          }
          .useSizeType({
            xs: { span: Constants.MIDDLE_XS_SPAN, offset: Constants.MIDDLE_XS_OFFSET },
            sm: { span: Constants.MIDDLE_SM_SPAN, offset: Constants.MIDDLE_SM_OFFSET },
            md: { span: Constants.MIDDLE_MD_SPAN, offset: Constants.MIDDLE_MD_OFFSET },
            lg: { span: Constants.MIDDLE_LG_SPAN, offset: Constants.MIDDLE_LG_OFFSET }
          })
          .height(Constants.FULL_HEIGHT)
          Row()
            .useSizeType({
              xs: { span: Constants.RIGHT_XS_SPAN, offset: Constants.RIGHT_XS_OFFSET },
              sm: { span: Constants.RIGHT_SM_SPAN, offset: Constants.RIGHT_SM_OFFSET },
              md: { span: Constants.RIGHT_MD_SPAN, offset: Constants.RIGHT_MD_OFFSET },
              lg: { span: Constants.RIGHT_LG_SPAN, offset: Constants.RIGHT_LG_OFFSET }
            })
            .height(Constants.FULL_HEIGHT)
            .backgroundColor(Color.White)
        }
        .height(Constants.FULL_HEIGHT)
      }
    }.backgroundColor(Color.White)
  }
}

@Component
struct mediaDocumentItem {
  @State mediaDocListItem: MeidaDocObj[] = []; // Permission information array
  @State mediaListItem: MediaListObj = {
    labelId: '',
    iconId: '',
    versionName: '',
    description: ''
  }; // application info array
  @State isCheckList: boolean[] = []; // Permission status array

  authorizeDialogController: CustomDialogController = new CustomDialogController({
    builder: authorizeDialog({ }),
    autoCancel: true,
    alignment: DialogAlignment.Center
  });

  /**
   * Grant permissions to the app
   * @param {Number} accessTokenId
   * @param {String} permission permission name
   */
  async grantUserGrantedPermission(accessTokenId, permission) {
    var permissionFlag =  await abilityAccessCtrl.createAtManager().
    getPermissionFlags(accessTokenId, permission);
    abilityAccessCtrl.createAtManager().grantUserGrantedPermission(
      accessTokenId, permission, permissionFlag).then(result => {
      // result: 0 Authorization succeeded; result: -1 Authorization failed
      if (result !== Constants.PERMISSION_INDEX) {
        this.authorizeDialogController.open();
        setTimeout(()=> {
          this.authorizeDialogController.close();
        }, Constants.DELAY_TIME)
      } else {
        this.isCheckList = [true, false];
      }
    }).catch(error => {
    })
  }

  /**
   * Deauthorize the app
   * @param {Number} accessTokenId
   * @param {String} permission permission name
   */
  async revokeUserGrantedPermission(accessTokenId, permission) {
    var permissionFlag =  await abilityAccessCtrl.createAtManager().
    getPermissionFlags(accessTokenId, permission);
    abilityAccessCtrl.createAtManager().revokeUserGrantedPermission(
      accessTokenId, permission, permissionFlag).then(result => {
      // result: 0 successfully cancel the authorization; result: -1 cancel the authorization failed
      if (result !== Constants.PERMISSION_INDEX) {
        this.authorizeDialogController.open();
        setTimeout(()=> {
          this.authorizeDialogController.close();
        }, Constants.DELAY_TIME)
      } else {
        this.isCheckList = [false, true];
      }
    })
  }

  /**
   * Lifecycle function, executed when the page is initialized
   */
  aboutToAppear() {
    let permissionDescription = permissionDescriptions[backTitle];
    bundle.getBundleInfo(routerData, Constants.PARMETER_BUNDLE_FLAG).then(res => {
      Promise.all([getAppLabel(res.appInfo.labelId, res.name),
      getAppIcon(res.appInfo.iconId, res.name)])
        .then((values) => {
          this.mediaListItem = new MediaListObj(
            String(values[0]), String(values[1]), res.versionName, permissionDescription);
        })
      this.mediaDocListItem.push(
        new MeidaDocObj(
          Constants.RADIO_ALLOW_NAME,
          Constants.RADIO_ALLOW_INDEX,
          Constants.RADIO_ALLOW_GROUP_NAME,
          res.appInfo.accessTokenId,
          permission
        )
      );
      this.mediaDocListItem.push(
        new MeidaDocObj(
          Constants.RADIO_BAN_NAME,
          Constants.RADIO_BAN_INDEX,
          Constants.RADIO_BAN_GROUP_NAME,
          res.appInfo.accessTokenId,
          permission
        )
      );
    }).catch(() => {
      this.mediaListItem = new MediaListObj('', '', '', permissionDescription);
      this.mediaDocListItem.push(
        new MeidaDocObj(Constants.RADIO_ALLOW_NAME, Constants.RADIO_ALLOW_INDEX,
          Constants.RADIO_ALLOW_GROUP_NAME, '', permission)
      );
      this.mediaDocListItem.push(
        new MeidaDocObj(Constants.RADIO_BAN_NAME, Constants.RADIO_BAN_INDEX,
          Constants.RADIO_BAN_GROUP_NAME, '', permission)
      );
    })
    // Get permission status
    if (!status) {
      this.isCheckList = [true, false];
    } else {
      this.isCheckList = [false, true];
    }
  }

  build(){
    Column() {
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Image(this.mediaListItem.iconId)
            .width(Constants.TERTIARY_IMAGE_WIDTH)
            .height(Constants.TERTIARY_IMAGE_HEIGHT)
            .margin({ left: Constants.TERTIARY_IMAGE_MARGIN_LEFT, right: Constants.TERTIARY_IMAGE_MARGIN_RIGHT })
          Column() {
            Row() {
              Text(this.mediaListItem.labelId)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontColor($r('app.color.title_text_color'))
                .textAlign(TextAlign.Start)
            }
            .width(Constants.TERTIARY_HALF_WIDTH)
            Row() {
              Text(this.mediaListItem.versionName)
                .fontSize(Constants.TEXT_SMALLER_FONT_SIZE)
                .textAlign(TextAlign.Start)
            }
            .width(Constants.TERTIARY_HALF_WIDTH)
          }
        }
      }
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Row() {
            Text(this.mediaListItem.description)
              .fontSize(Constants.TEXT_SMALLER_FONT_SIZE)
              .textAlign(TextAlign.Start)
          }.margin({ left: Constants.TERTIARY_IMAGE_MARGIN_LEFT, right: Constants.TERTIARY_IMAGE_MARGIN_RIGHT })
        }
      }
      .margin({ top: Constants.TERTIARY_ROW_MARGIN_TOP })
      Row() {
        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
          Row() {
            Text(backTitle + '访问权限')
              .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
              .textAlign(TextAlign.Start)
          }.margin({ left: Constants.TERTIARY_IMAGE_MARGIN_LEFT, right: Constants.TERTIARY_IMAGE_MARGIN_RIGHT })
        }
      }
      .height(Constants.LISTITEM_ROW_HEIGHT)
      .margin({ top: Constants.TERTIARY_PERMISSION_ROW_MARGIN_TOP })
      Column() {
        List() {
          ForEach(this.mediaDocListItem, (item) => {
            ListItem() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                    Row() {
                      Text(item.name)
                        .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                        .fontColor($r('app.color.text_color'))
                        .flexGrow(Constants.FLEX_GROW)
                      if (this.isCheckList[item.index] === true) {
                        Image($r('app.media.radioactive'))
                          .width(Constants.TERTIARY_RADIO_IMAGE_WIDTH)
                          .height(Constants.TERTIARY_RADIO_IMAGE_HEIGHT)
                          .margin({
                            top: Constants.TERTIARY_RADIO_IMAGE_MARGIN_TOP
                          })
                      } else if (this.isCheckList[item.index] === false) {
                        Image($r('app.media.radiodefault'))
                          .width(Constants.TERTIARY_RADIO_IMAGE_WIDTH)
                          .height(Constants.TERTIARY_RADIO_IMAGE_HEIGHT)
                          .margin({
                            top: Constants.TERTIARY_RADIO_IMAGE_MARGIN_TOP
                          })
                      }
                    }
                    .backgroundColor($r('app.color.default_background_color'))
                    .width(Constants.FULL_WIDTH)
                    .height(Constants.LISTITEM_ROW_HEIGHT)
                    .onClick(() => {
                      if (item.accessTokenId !== '' || item.permission !== ''){
                        if (!item.index) {
                          this.grantUserGrantedPermission(item.accessTokenId, item.permission);
                        } else {
                          this.revokeUserGrantedPermission(item.accessTokenId, item.permission);
                        }
                      }
                    })
                  }
                }
                if (!item.index) {
                  Row() {
                    Column()
                      .backgroundColor($r('app.color.text_decoration_color'))
                      .width(Constants.FULL_WIDTH)
                      .height(Constants.TEXT_DECORATION_HEIGHT)
                  }
                }
              }
              .onClick(() => {
              })
            }
            .padding({
              left: Constants.TERTIARY_LISTITEM_PADDING_LEFT,
              right: Constants.TERTIARY_LISTITEM_PADDING_RIGHT
            })
            .margin({ top: Constants.TERTIARY_LISTITEM_MARGIN_TOP })
          }, item => item.toString())
        }
        .borderRadius(Constants.BORDER_RADIUS)
        .backgroundColor($r('app.color.default_background_color'))
        .padding({
          left: Constants.TERTIARY_LIST_PADDING_LEFT, right: Constants.TERTIARY_LIST_PADDING_RIGHT,
          top: Constants.TERTIARY_LIST_PADDING_TOP, bottom: Constants.TERTIARY_LIST_PADDING_BOTTOM
        })
      }
      .padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
      .width(Constants.FULL_WIDTH)
      .height(Constants.FULL_HEIGHT)
      .backgroundColor($r('app.color.background_color'))
    }
    .backgroundColor($r('app.color.background_color')).width(Constants.FULL_WIDTH)
  }
}
