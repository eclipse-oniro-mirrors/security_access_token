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
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import { groups } from "../common/model/permissionGroup.ets";
import Constants from '../common/utils/constant.ets';

var TAG = 'PermissionManager_MainAbility:'

const allowedStatus = 0; // Status: Allowed
const bannedStatus = 1; // Status: Banned

class AllowedObj {
  groupName: string;
  permission: string[];
  constructor(groupName: string, permission: string[]) {
    this.groupName = groupName;
    this.permission = permission;
  }
} // Class Allowed
class BannedObj {
  groupName: string;
  permission: string[];
  constructor(groupName: string, permission: string[]) {
    this.groupName = groupName;
    this.permission = permission;
  }
} // Class Banned

@Entry
@Component
struct appNamePlusPage {
  @State allowedListItem: AllowedObj[] = []; // Array of allowed permissions
  @State bannedListItem: BannedObj[] = []; // array of forbidden permissions
  private routerData = router.getParams().routerData; // Routing jump data

  @Builder ListItemLayout(item, index, status) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Column() {
                Row() {
                  Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                    Text(item.groupName)
                      .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                      .fontColor($r('app.color.text_color'))
                  }.margin({ top: Constants.FLEX_MARGIN_TOP, bottom: Constants.FLEX_MARGIN_BOTTOM })
                }.height(Constants.FULL_HEIGHT)
              }.flexGrow(Constants.FLEX_GROW).constraintSize({ minHeight: Constants.CONSTRAINTSIZE_MINHEIGHT })
              Image($r('app.media.rightarrow'))
                .objectFit(ImageFit.Contain)
                .height(Constants.IMAGE_HEIGHT)
                .width(Constants.IMAGE_WIDTH)
            }
            .width(Constants.FULL_WIDTH)
            .height(Constants.LISTITEM_ROW_HEIGHT)
          }
          if (!index) {
            Row() {
              Column()
                .backgroundColor($r('app.color.text_decoration_color'))
                .width(Constants.FULL_WIDTH)
                .height(Constants.TEXT_DECORATION_HEIGHT)
            }
          }
        }.onClick(() => {
          if (status === 'allow') {
            if (item.groupName == "其他权限") {
              router.push({
                uri: 'pages/other-permissions',
                params: {
                  routerData: this.routerData.bundleName,
                  backTitle: item.groupName,
                  permission: item.permission,
                  status: allowedStatus,
                  tokenId: this.routerData.tokenId
                }
              });
            } else {
              router.push({
                uri: 'pages/application-tertiary',
                params: {
                  routerData: this.routerData.bundleName,
                  backTitle: item.groupName,
                  permission: item.permission,
                  status: allowedStatus
                }
              });
            }
          }
          else if (status === 'banned') {
            if (item.groupName == "其他权限") {
              router.push({
                uri: 'pages/other-permissions',
                params: {
                  routerData: this.routerData.bundleName,
                  backTitle: item.groupName,
                  permission: item.permission,
                  status: bannedStatus,
                  tokenId: this.routerData.tokenId
                }
              });
            } else {
              router.push({
                uri: 'pages/application-tertiary',
                params: {
                  routerData: this.routerData.bundleName,
                  backTitle: item.groupName,
                  permission: item.permission,
                  status: bannedStatus
                }
              });
            }
          }
        })
      }
    }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
  }

  /**
   * Initialize permission status information and group permission information
   */
  async initialPermissions() {
    var reqPermissions = this.routerData.permissions;
    var reqGroupIds = this.routerData.groupId;

    if (!reqGroupIds.length) {
      this.allowedListItem = [];
      this.bannedListItem = [];
      return;
    }

    for (let i = 0; i < reqGroupIds.length; i++) {
      let id = reqGroupIds[i];
      let groupName = groups[id].groupName;
      let groupReqPermissons = [];
      for (let j = 0; j < reqPermissions.length; j++) {
        let permission = reqPermissions[j];
        if (groups[id].permissions.indexOf(permission) != -1) {
          groupReqPermissons.push(permission)
        }
      }
      let isGranted = true;
      for (let i = 0; i < groupReqPermissons.length; i++) {
        let permission = groupReqPermissons[i]
        let res = await abilityAccessCtrl.createAtManager().verifyAccessToken(
          this.routerData.tokenId, permission);
        if (res != 0) {
          isGranted = false;
        }
      }

      if (isGranted) {
        this.allowedListItem.push(new AllowedObj(groupName, groupReqPermissons));
      } else {
        this.bannedListItem.push(new BannedObj(groupName, groupReqPermissons));
      }
    }
  }

  /**
   * Lifecycle function, triggered once when this page is displayed
   */
  onPageShow() {
    console.log(TAG + 'onPageShow application-secondary')
    this.initialPermissions();
  }

  /**
   * Lifecycle function, triggered once when this page disappears
   */
  onPageHide() {
    console.log(TAG + 'onPageHide application-secondary')
    setTimeout(()=> {
      this.allowedListItem = [];
      this.bannedListItem = [];
    }, Constants.DELAY_TIME)
  }

  build() {
    Column(){
      GridContainer({ gutter: Constants.GUTTER, margin: Constants.GRID_MARGIN }) {
        Row({}) {
          Row()
            .useSizeType({
              xs: { span: Constants.LEFT_XS_SPAN, offset: Constants.LEFT_XS_OFFSET },
              sm: { span: Constants.LEFT_SM_SPAN, offset: Constants.LEFT_SM_OFFSET },
              md: { span: Constants.LEFT_MD_SPAN, offset: Constants.LEFT_MD_OFFSET },
              lg: { span: Constants.LEFT_LG_SPAN, offset: Constants.LEFT_LG_OFFSET }
            })
            .height(Constants.FULL_HEIGHT)
          Row() {
            Column() {
              Row() {
                backBar({ title: JSON.stringify(this.routerData.labelId) })
              }
              Row() {
                Column() {
                  if (!this.allowedListItem.length && !this.bannedListItem.length) {
                    Row() {
                      List() {
                        ListItem() {
                          Row() {
                            Column() {
                              Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                                Row() {
                                  Column() {
                                    Row() {
                                      Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                                        Text($r('app.string.no_permission'))
                                          .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                                          .fontColor($r('app.color.text_color'))
                                      }.margin({ top: Constants.FLEX_MARGIN_TOP, bottom: Constants.FLEX_MARGIN_BOTTOM })
                                    }.height(Constants.FULL_HEIGHT)
                                  }.flexGrow(Constants.FLEX_GROW)
                                   .constraintSize({minHeight: Constants.CONSTRAINTSIZE_MINHEIGHT })
                                }
                                .width(Constants.FULL_WIDTH)
                                .height(Constants.LISTITEM_ROW_HEIGHT)
                              }
                            }
                          }
                        }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
                      }
                      .backgroundColor($r('app.color.default_background_color'))
                      .borderRadius(Constants.BORDER_RADIUS)
                      .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                    }.margin({ top: Constants.ROW_MARGIN_TOP })
                     .padding({ left: Constants.SECONDARY_LIST_PADDING_LEFT, right: Constants.SECONDARY_LIST_PADDING_RIGHT })
                  } else {
                    if (this.allowedListItem.length) {
                      Row() {
                        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                          Text($r('app.string.allowed'))
                            .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                            .margin({
                              top: Constants.SECONDARY_TEXT_MARGIN_TOP,
                              left: Constants.SECONDARY_LIST_PADDING_RIGHT
                            })
                        }
                      }
                      Row() {
                        List() {
                          ForEach(this.allowedListItem.slice(Constants.SLICE_START, this.allowedListItem.length - 1),
                          (item) => {
                            this.ListItemLayout(item, Constants.SLICE_START_INDEX, 'allow')
                          }, item => item.toString())
                          ForEach(this.allowedListItem.slice(Constants.SLICE_END), (item, index) => {
                            this.ListItemLayout(item, Constants.SLICE_END_INDEX, 'allow')
                          }, item => item.toString())
                        }
                        .backgroundColor($r('app.color.default_background_color'))
                        .borderRadius(Constants.BORDER_RADIUS)
                        .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                      }.margin({ top: Constants.ROW_MARGIN_TOP })
                       .padding({ left: Constants.SECONDARY_LIST_PADDING_LEFT, right: Constants.SECONDARY_LIST_PADDING_RIGHT })
                    }
                    if (this.bannedListItem.length) {
                      Row() {
                        Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
                          Text($r('app.string.banned'))
                            .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                            .margin({
                              top: Constants.SECONDARY_TEXT_MARGIN_TOP,
                              left: Constants.SECONDARY_LIST_PADDING_RIGHT
                            })
                        }
                      }
                      Row() {
                        List() {
                          ForEach(this.bannedListItem.slice(Constants.SLICE_START, this.bannedListItem.length - 1),
                          (item) => {
                            this.ListItemLayout(item, Constants.SLICE_START_INDEX, 'banned')
                          }, item => item.toString())
                          ForEach(this.bannedListItem.slice(Constants.SLICE_END), (item) => {
                            this.ListItemLayout(item, Constants.SLICE_END_INDEX, 'banned')
                          }, item => item.toString())
                        }
                        .backgroundColor($r('app.color.default_background_color'))
                        .borderRadius(Constants.BORDER_RADIUS)
                        .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                      }.margin({ top: Constants.ROW_MARGIN_TOP })
                       .padding({ left: Constants.SECONDARY_LIST_PADDING_LEFT, right: Constants.SECONDARY_LIST_PADDING_RIGHT })
                    }
                  }
                }
                .width(Constants.FULL_WIDTH)
                .height(Constants.FULL_HEIGHT)
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
        }
        .height(Constants.FULL_HEIGHT)
        .width(Constants.FULL_WIDTH)
        .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
        .opacity(Constants.MANAGEMENT_TRANSPARENCY)
      }
    }
  }
}
