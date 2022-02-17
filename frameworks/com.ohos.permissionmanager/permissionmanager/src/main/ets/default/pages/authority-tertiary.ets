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
import { alphabetIndexerComponent } from "../common/components/alphabeticalIndex.ets";
import { textInput } from "../common/components/search.ets";
import router from '@system.router';
import bundle from "@ohos.bundle";
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import { getAppLabel, getAppIcon, verifyAccessToken, changeIndexValue } from "../common/utils/utils";
import { makePy } from "../common/utils/utils.ets";
import { authorizeDialog } from "../common/components/dialog.ets";
import Constants from '../common/utils/constant.ets';

@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
}

let routerData = router.getParams().routerData; // Routing jump data
let backTitle = router.getParams().backTitle; // return title name
class ApplicationObj {
  labelId: string
  iconId: string
  index: number
  accessTokenId: string
  permission: string
  alphabeticalIndex: string
  constructor(
    labelId: string,
    iconId: string,
    index: number,
    accessTokenId: string,
    permission: string,
    alphabeticalIndex: string) {
    this.labelId = labelId
    this.iconId = iconId
    this.index = index
    this.accessTokenId = accessTokenId
    this.permission = permission
    this.alphabeticalIndex = alphabeticalIndex
  }
} // application information

@Entry
@Component
struct locationInfoPage {
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
                applicationItem()

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
      }
      .height(Constants.FULL_HEIGHT)
    }
  }
}

@Component
struct applicationItem {
  @State toggleIsOn: boolean[] = []; // toggle switch state array
  @State applicationList: ApplicationObj[] = []; // application info array
  @State oldApplicationItem: ApplicationObj[] = []; // Original application information array
  @State searchResult: boolean = true; // search results

  authorizeDialogController: CustomDialogController = new CustomDialogController({
    builder: authorizeDialog({ }),
    autoCancel: true,
    alignment: DialogAlignment.Center
  });

  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Image(item.iconId)
                .customizeImage(Constants.AUTHORITY_IMAGE_WIDTH, Constants.AUTHORITY_IMAGE_HEIGHT)
                .margin({ right: Constants.AUTHORITY_IMAGE_MARGIN_RIGHT })
              Text(item.labelId)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontColor($r('app.color.text_color'))
                .flexGrow(Constants.FLEX_GROW)
              Toggle({ type: ToggleType.Switch, isOn: this.toggleIsOn[item.index] })
                .selectedColor($r('app.color.toggle_color'))
                .width(Constants.AUTHORITY_TOGGLE_WIDTH)
                .height(Constants.AUTHORITY_TOGGLE_HEIGHT)
                .onChange((isOn: boolean) => {
                  if (item.accessTokenId === '' || item.permission === '') {
                    return;
                  }
                  if (isOn) {
                    this.grantUserGrantedPermission(item.accessTokenId, item.permission, item.index);
                  } else {
                    this.revokeUserGrantedPermission(item.accessTokenId, item.permission, item.index);
                  }
                })
            }
            .width(Constants.FULL_WIDTH)
            .height(Constants.AUTHORITY_ROW_HEIGHT)
            .constraintSize({ minHeight: Constants.AUTHORITY_CONSTRAINTSIZE_MINHEIGHT })
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
        })
      }
    }.padding({ left: Constants.AUTHORITY_LISTITEM_PADDING_LEFT, right: Constants.AUTHORITY_LISTITEM_PADDING_RIGHT })
  }

  /**
   * Grant permissions to the app
   * @param {Number} accessTokenId
   * @param {String} permission permission name
   * @param {Number} index Array index to modify permission status
   */
  async grantUserGrantedPermission(accessTokenId, permission, index) {
    var permissionFlag =  await abilityAccessCtrl.createAtManager().
      getPermissionFlags(accessTokenId, permission);
    abilityAccessCtrl.createAtManager().grantUserGrantedPermission(
      accessTokenId, permission, permissionFlag).then(result => {
      // result: 0 Authorization succeeded; result: -1 Authorization failed
      if (result !== Constants.PERMISSION_INDEX) {
        this.authorizeDialogController.open();
        this.toggleIsOn = changeIndexValue(this.toggleIsOn, [[index, false]]);
        setTimeout(()=> {
          this.authorizeDialogController.close();
        }, Constants.DELAY_TIME)
      } else {
        this.toggleIsOn = changeIndexValue(this.toggleIsOn, [[index, true]]);
      }
    }).catch(error => {
    })
  }

  /**
   * Deauthorize the app
   * @param {Number} accessTokenId
   * @param {String} permission permission name
   * @param {Number} index Array index to modify permission status
   */
  async revokeUserGrantedPermission(accessTokenId, permission, index) {
    var permissionFlag =  await abilityAccessCtrl.createAtManager().
    getPermissionFlags(accessTokenId, permission);
    abilityAccessCtrl.createAtManager().revokeUserGrantedPermission(
      accessTokenId, permission, permissionFlag).then(result => {
      // result: 0 successfully cancel the authorization; result: -1 cancel the authorization failed
      if (result !== Constants.PERMISSION_INDEX) {
        this.authorizeDialogController.open();
        this.toggleIsOn = changeIndexValue(this.toggleIsOn, [index, false]);
        setTimeout(()=> {
          this.authorizeDialogController.close();
        }, Constants.DELAY_TIME)
      } else {
        this.toggleIsOn = changeIndexValue(this.toggleIsOn, [index, true]);
      }
    })
  }

  /**
   * Lifecycle function, executed when the page is initialized
   */
  aboutToAppear() {
    for (let i = 0; i < routerData[0].bundleNames.length; i++) {
      // Get BundleInfo based on bundle name
      bundle.getBundleInfo(routerData[0].bundleNames[i], Constants.PARMETER_BUNDLE_FLAG).then(res => {
        Promise.all([getAppLabel(res.appInfo.labelId, res.name),
          getAppIcon(res.appInfo.iconId, res.name),
          verifyAccessToken(res.appInfo.accessTokenId, routerData[0].permission)])
          .then((values) => {
          this.applicationList.push(
            new ApplicationObj(
              String(values[0]),
              String(values[1]),
              i,
              res.appInfo.accessTokenId,
              routerData[0].permission,
              makePy(values[0])[0].slice(0, 1)) // Get the first letter in the returned initials array
          );
          this.oldApplicationItem.push(
            new ApplicationObj(
              String(values[0]),
              String(values[1]),
              i,
              res.appInfo.accessTokenId,
              routerData[0].permission,
              makePy(values[0])[0].slice(0, 1)) // Get the first letter in the returned initials array
          );
          // 0: have permission; -1: no permission
          if (values[2] === Constants.PERMISSION_INDEX) {
            this.toggleIsOn.push(true);
          } else {
            this.toggleIsOn.push(false);
          }
          });
      }).catch(() => {
        this.applicationList.push(
          new ApplicationObj('', '', 0, '', '', '')
        );
        this.oldApplicationItem.push(
          new ApplicationObj('', '', 0, '', '', '')
        );
      })
    }
  }

  build() {
    Column() {
      Row() {
        textInput({
          placeholder: $r('app.string.textInput_placeholder'),
          applicationItem: $applicationList,
          oldApplicationItem: $oldApplicationItem,
          searchResult: $searchResult
        })
      }.padding({
        left: Constants.AUTHORITY_TEXTINPUT_PADDING_LEFT,
        right: Constants.AUTHORITY_TEXTINPUT_PADDING_RIGHT
      })
      .backgroundColor($r('app.color.background_color'))
      Row() {
        Flex({ alignItems:ItemAlign.Start, justifyContent: FlexAlign.Start }) {
          Column() {
            Flex({ justifyContent: FlexAlign.Start }) {
              Text(this.applicationList.length + '个应用获取此权限')
                .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                .fontColor($r('app.color.secondary_font_color'))
                .margin({ top: Constants.AUTHORITY_TEXT_MARGIN_TOP, left: Constants.AUTHORITY_TEXT_MARGIN_LEFT })
            }
            Scroll() {
              Row() {
                Column() {
                  if (!this.applicationList.length) {
                    if (this.searchResult) {
                      Row() {
                      }.margin({ top: Constants.AUTHORITY_ROW_MARGIN_TOP })
                    } else {
                      Row() {
                        Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
                          Image($r('app.media.searchnoresult'))
                            .customizeImage(Constants.SEARCHNORESULT_IMAGE_WIDTH, Constants.SEARCHNORESULT_IMAGE_HEIGHT)
                        }
                      }.margin({ top: Constants.AUTHORITY_ROW_MARGIN_TOP })
                    }
                  } else {
                    Row() {
                      List() {
                        ForEach(this.applicationList.slice(Constants.SLICE_START, this.applicationList.length - 1),
                        (item) => {
                          this.ListItemLayout(item, Constants.SLICE_START_INDEX)
                        }, item => item.toString())
                        ForEach(this.applicationList.slice(Constants.SLICE_END), (item, index) => {
                          this.ListItemLayout(item, Constants.SLICE_END_INDEX)
                        }, item => item.toString())
                      }
                      .backgroundColor($r('app.color.default_background_color'))
                      .borderRadius(Constants.BORDER_RADIUS)
                      .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                    }.margin({ top: Constants.AUTHORITY_ROW_MARGIN_TOP })
                  }
                }.width(Constants.FULL_WIDTH)
                .height(Constants.AUTHORITY_COLUMN_HEIGHT)
                .backgroundColor($r('app.color.background_color'))
              }
            }
          }.padding({ left: Constants.AUTHORITY_LISTITEM_PADDING_LEFT })
          Column() {
            alphabetIndexerComponent({ applicationItem: $applicationList, oldApplicationItem: $oldApplicationItem })
          }.width(Constants.AUTHORITY_ALPHABETINDEX_WIDTH)
           .padding({ top: Constants.AUTHORITY_ALPHABETINDEX_PADDING_TOP })
        }
      }
      .backgroundColor($r('app.color.background_color'))
    }
  }
}
