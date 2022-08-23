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

import { backBar } from "../common/components/backBar";
import router from '@system.router';
import Constants from '../common/utils/constant';
import { permissionGroups } from '../common/model/permissionGroup'
import abilityAccessCtrl from '@ohos.abilityAccessCtrl'

var TAG = 'PermissionManager_MainAbility:'

let routerData = router.getParams().routerData; // Routing jump data
let tokenId: any = router.getParams().tokenId; // tokenId for verify permission
let backTitle = router.getParams().backTitle; // return title name
let status = router.getParams().status; // Status: Allowed, Forbidden
let permissions: any = router.getParams().permission; // permissions name
let otherPermissionList = []; // otherPermission List
for (let i = 0; i < permissions.length; i++) {
  otherPermissionList.push({
    permissionLabel: permissionGroups.filter(item => item.permissionName == permissions[i])[0].label,
    permission: permissions[i]
  })
}

@Entry
@Component
struct appNamePage {
  build() {
    GridContainer({ gutter: Constants.GUTTER, margin: Constants.GRID_MARGIN }) {
      Row() {
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
              backBar({ title: JSON.stringify(backTitle), recordable: false })
            }
            Row() {
              Column() {
                Scroll() {
                  appNameItem()
                }
              }
            }.layoutWeight(Constants.LAYOUT_WEIGHT)
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

/**
   * Lifecycle function, triggered once when this page is displayed
   */
  onPageShow() {
    console.log(TAG + 'onPageShow other-permissions')
    let isGranted = true;
    permissions.forEach(permission => {
      abilityAccessCtrl.createAtManager().verifyAccessToken(tokenId, permission).then(res => {
        status = res;
      })
        .catch(err => {
          console.error(TAG + 'verifyAccessToken occure error: ' + JSON.stringify(err))
        })
    })
  }
}

@Component
struct appNameItem {
  @State otherPermissionListItem: string[] = otherPermissionList; // Other permission interface data array
  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Text(item.permissionLabel)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontColor($r('app.color.text_color'))
                .flexGrow(Constants.FLEX_GROW)
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
            router.push({
              uri: 'pages/application-tertiary',
              params: {
                routerData: routerData,
                backTitle: item.permissionLabel,
                permission: [item.permission],
                status: status
              }
            });
        })
      }
    }.padding({ left: Constants.DEFAULT_PADDING_START, right: Constants.DEFAULT_PADDING_END })
  }

  build() {
    Row() {
      Column() {
        Row() {
          List() {
            ForEach(this.otherPermissionListItem.slice(Constants.SLICE_START, this.otherPermissionListItem.length - 1),
            (item) => {
              this.ListItemLayout(item, Constants.SLICE_START_INDEX)
            }, item => item.toString())
            ForEach(this.otherPermissionListItem.slice(Constants.SLICE_END), (item, index) => {
              this.ListItemLayout(item, Constants.SLICE_END_INDEX)
            }, item => item.toString())
          }.backgroundColor($r('app.color.default_background_color')).borderRadius(Constants.BORDER_RADIUS)
           .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
        }.margin({ top: Constants.ROW_MARGIN_TOP })
         .padding({ left: Constants.LIST_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
      }
      .width(Constants.FULL_WIDTH)
      .height(Constants.FULL_HEIGHT)
    }
  }
}
