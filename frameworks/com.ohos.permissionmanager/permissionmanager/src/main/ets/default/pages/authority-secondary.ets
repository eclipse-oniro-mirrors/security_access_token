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
import { permissionGroups, groups } from "../common/model/permissionGroup.ets";
import router from '@system.router';
import Constants from '../common/utils/constant.ets';

class CalendarObj {
  permissionName: string
  groupName: string
  description: string
  label: string
  constructor(permissionName: string, groupName: string, description: string, label: string) {
    this.permissionName = permissionName
    this.groupName = groupName
    this.description = description
    this.label = label
  }
} // Permission management secondary interface data class

@Entry
@Component
struct appNamePage {
  private backTitle = router.getParams().backTitle; // return title name

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
              backBar({ title: JSON.stringify(this.backTitle) })
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
          var dataList = this.routerData.filter((ele) => {
            return ele.groupName === item.groupName;
          })
          router.push({
            uri: 'pages/authority-tertiary',
            params: { routerData: dataList, backTitle: item.label }
          });
        })
      }
    }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
  }

  /**
   * Lifecycle function, executed when the page is initialized
   */
  aboutToAppear() {
    var permissionsListNomal = groups.filter((item) => {
      return item.groupName === this.backTitle;
    });
    var permissionsListOther = groups.filter((item) => {
      return  item.children !== undefined;
    })[0].children.filter((item) => {
      return  item.groupName === this.backTitle;
    });
    var arraySort = [];
    for (let i = 0; i < permissionsListOther[0].permissions.length; i++) {
      if (arraySort.indexOf(permissionsListOther[0].permissions[i]) === -1) {
        arraySort.push(permissionsListOther[0].permissions[i]);
      }
    }
    permissionsListOther[0].permissions = arraySort;
    var permissionsList;
    if (permissionsListNomal.length) {
      permissionsList = permissionsListNomal;
    }
    if (permissionsListOther.length) {
      permissionsList = permissionsListOther;
    }
    for (let i = 0; i < permissionsList[0].permissions.length; i++) {
      permissionGroups.forEach((item) => {
        if (item.permissionName === permissionsList[0].permissions[i]) {
          this.calendarListItem.push(
            new CalendarObj(item.permissionName, item.groupName, item.description, item.label)
          )
        }
      })
    }
  }

  build() {
    Row() {
      Column() {
        if (!this.calendarListItem.length) {
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
                              Text($r('app.string.no_data'))
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
          .padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
        } else {
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
          .padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
        }
      }
      .width(Constants.FULL_WIDTH)
      .height(Constants.FULL_HEIGHT)
      .backgroundColor($r('app.color.background_color'))
    }
  }
}
