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
import Constants from '../common/utils/constant.ets';
import { otherPermissionsLabel } from '../common/model/permissionGroup.ets'

let routerData = router.getParams().routerData; // Routing jump data
let backTitle = router.getParams().backTitle; // return title name
let status = router.getParams().status; // Status: Allowed, Forbidden
let permissions = router.getParams().permission; // permissions name
let otherPermissionList = []; // otherPermission List
for (let i = 0; i < permissions.length; i++) {
  otherPermissionList.push({
    permissionLabel: otherPermissionsLabel[permissions[i]],
    permission: permissions[i]
  })
}

@Entry
@Component
struct appNamePage {
  build() {
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
        Row() {
          Column() {
            Row() {
              backBar({ title: JSON.stringify(backTitle) })
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
    }
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
                backTitle: backTitle,
                permission: [item.permission],
                status: status
              }
            });
        })
      }
    }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
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
      .backgroundColor($r('app.color.background_color'))
    }
  }
}
