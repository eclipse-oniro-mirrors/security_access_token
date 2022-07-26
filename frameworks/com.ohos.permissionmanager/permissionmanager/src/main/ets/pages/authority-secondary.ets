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
import { permissionGroups, groups } from "../common/model/permissionGroup";
import router from '@system.router';
import Constants from '../common/utils/constant';

var TAG = 'PermissionManager_MainAbility:'

class CalendarObj {
  permissionName: string
  groupName: string
  description: string
  label: string
  index: number
  constructor(permissionName: string, groupName: string, description: string, label: string, index: number) {
    this.permissionName = permissionName
    this.groupName = groupName
    this.description = description
    this.label = label
    this.index = index
  }
} // Permission management secondary interface data class

@Entry
@Component
struct appNamePage {
  private backTitle = router.getParams().backTitle; // return title name

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
              backBar({ title: JSON.stringify(this.backTitle), recordable: false })
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
}

@Component
struct appNameItem {
  @State calendarListItem: CalendarObj[] = []; // Permission management secondary interface data array
  private routerData = router.getParams().routerData; // Routing jump data
  private backTitle = router.getParams().backTitle; // return title name
  private allPermissionApplications = router.getParams().allPermissionApplications; // Array of all app permission names

  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Text(item.label)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontColor($r('app.color.label_color'))
                .fontWeight(FontWeight.Medium)
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
          var dataList = this.routerData.filter((ele) => {
            return ele.groupName === item.groupName;
          })
          router.push({
            uri: 'pages/authority-tertiary',
            params: { routerData: [dataList[item.index]], backTitle: item.label }
          });
        })
      }
    }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
  }

  /**
   * Lifecycle function, executed when the page is initialized
   */
  aboutToAppear() {
    var permissionsList = groups.filter((item) => {
      return item.groupName === this.backTitle
    })
    for (let i = 0; i < permissionsList[0].permissions.length; i++) {
      permissionGroups.forEach((item) => {
        if (item.permissionName === permissionsList[0].permissions[i]) {
          this.calendarListItem.push(
            new CalendarObj(item.permissionName, item.groupName, item.description, item.label, i)
          )
        }
      })
    }
  }

  build() {
    Row() {
      Column() {
        Row() {
            List() {
              ForEach(this.calendarListItem.slice(Constants.SLICE_START, this.calendarListItem.length - 1), (item) => {
                this.ListItemLayout(item, Constants.SLICE_START_INDEX)
              }, item => item.toString())
              ForEach(this.calendarListItem.slice(Constants.SLICE_END), (item, index) => {
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
