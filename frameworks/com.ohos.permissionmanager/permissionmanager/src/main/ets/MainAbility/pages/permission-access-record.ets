/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import bundle from '@ohos.bundle';
import router from '@system.router';
import Resmgr from '@ohos.resourceManager'
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import privacyManager from '@ohos.privacyManager'
import { backBar } from "../common/components/backBar.ets";
import Constants from '../common/utils/constant.ets';
import { groups, noNeedDisplayApp, userGrantPermissions, permissionGroupIds } from "../common/model/permissionGroup.ets";
import { getPermissionGroup } from '../common/utils/utils.ets'

var TAG = 'PermissionManager_MainAbility:'

@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
};

@Entry
@Component
struct permissionRecordPage {
  @State applicationInfos: any[] = []
  @State appInfos: any[] = []
  @State permissionApplications: any[] = []
  @State permissionIndex: number = -1
  @State applicationIndex: number = -1
  @State strings: any = {}

  @Builder ListItemLayout(item, index, dimension) {
    ListItem() {
      Column() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              if(dimension) {
                Image(item.icon)
                  .customizeImage(Constants.MANAGEMENT_IMAGE_WIDTH, Constants.MANAGEMENT_IMAGE_HEIGHT)
                  .margin({ right: Constants.MANAGEMENT_IMAGE_MARGIN_RIGHT_RECORD, left: Constants.MANAGEMENT_IMAGE_MARGIN_LEFT })
              }else {
                Image(item.icon)
                  .customizeImage(Constants.APPLICATION_IMAGE_WIDTH, Constants.APPLICATION_IMAGE_HEIGHT)
                  .margin({ right: Constants.MANAGEMENT_IMAGE_MARGIN_RIGHT })
              }
              Column() {
                Text(item.groupName)
                  .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('app.color.label_color'))
                  .lineHeight(Constants.TEXT_LINE_HEIGHT)
                  .margin({ bottom: Constants.TERTIARY_LABEL_MARGIN_BOTTOM })
                if(dimension) {
                  Text($r("app.string.visits"))
                    .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                    .fontColor($r('app.color.label_color_light'))
                    .lineHeight(Constants.TEXT_SMALL_LINE_HEIGHT)
                }else {
                  Row() {
                    if (item.permissions) {
                      ForEach(item.permissions, permission => {
                        Image(permission.icon)
                          .customizeImage(Constants.IMAGE_WIDTH_RECORD_APPLICATION, Constants.IMAGE_HEIGHT_RECORD_APPLICATION)
                          .margin({ right: Constants.APPLICATION_TEXT_MARGIN_RIGHT })
                      })
                    }
                  }
                }
              }.flexGrow(Constants.FLEX_GROW)
              .alignItems(HorizontalAlign.Start)
              if(dimension) {
                if(index == this.permissionIndex) {
                  Image($r('app.media.xiangshangjiantou'))
                    .customizeImage(Constants.IMAGE_WIDTH_RECORD, Constants.IMAGE_HEIGHT_RECORD)
                }else {
                  Image($r('app.media.xiangxiajiantou'))
                    .customizeImage(Constants.IMAGE_WIDTH_RECORD, Constants.IMAGE_HEIGHT_RECORD)
                }
              }else {
                if(index == this.applicationIndex) {
                  Image($r('app.media.xiangshangjiantou'))
                    .customizeImage(Constants.IMAGE_WIDTH_RECORD, Constants.IMAGE_HEIGHT_RECORD)
                }else {
                  Image($r('app.media.xiangxiajiantou'))
                    .customizeImage(Constants.IMAGE_WIDTH_RECORD, Constants.IMAGE_HEIGHT_RECORD)
                }
              }
            }
            .width(Constants.FULL_WIDTH)
            .height(dimension ? Constants.LISTITEM_HEIGHT_PERMISSION : Constants.LISTITEM_HEIGHT_APPLICATION)
          }
        }.onClick(() => {
          dimension ?
            (this.permissionIndex = this.permissionIndex == index ? -1 : index) :
            (this.applicationIndex = this.applicationIndex == index ? -1 : index)
          if(dimension) {
            this.permissionApplications = this.appInfos.filter(appInfo => {
              return appInfo.groupIds.includes(index.toString())
            })
          }else {
            this.getRecords(item.accessTokenId, index)
          }
        })
        if(dimension && (index == this.permissionIndex)) {
          List() {
            ForEach(this.permissionApplications, (permissionApplication) => {
              ListItem() {
                Row() {
                  Image(permissionApplication.icon)
                    .customizeImage(Constants.APPLICATION_IMAGE_WIDTH, Constants.APPLICATION_IMAGE_HEIGHT)
                    .margin({ right: Constants.MANAGEMENT_IMAGE_MARGIN_RIGHT })
                  Column() {
                    Row().width(Constants.FULL_WIDTH).height(Constants.TEXT_DECORATION_HEIGHT)
                      .backgroundColor($r("app.color.label_color_lightest"))
                      .margin({ bottom: Constants.LISTITEM_MARGIN_BOTTOM_PERMISSION })
                    Text(permissionApplication.groupName)
                      .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                      .fontWeight(FontWeight.Medium)
                      .fontColor($r('app.color.label_color'))
                      .lineHeight(Constants.TEXT_LINE_HEIGHT)
                      .margin({ bottom: Constants.TERTIARY_LABEL_MARGIN_BOTTOM })
                    Text($r("app.string.visits"))
                      .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                      .fontColor($r('app.color.label_color_light'))
                      .lineHeight(Constants.TEXT_SMALL_LINE_HEIGHT)
                  }.alignItems(HorizontalAlign.Start)
                  .height(Constants.FULL_HEIGHT)
                }
              }.height(Constants.LISTITEM_HEIGHT_PERMISSION)
              .onClick(() => {
                router.push({
                  uri: 'pages/application-secondary',
                  params: { routerData: {
                    'bundleName': permissionApplication.name,
                    'tokenId': permissionApplication.accessTokenId,
                    'iconId': permissionApplication.icon,
                    'labelId': permissionApplication.groupName,
                    'permissions': permissionApplication.reqUserPermissions,
                    'groupId': permissionApplication.groupIds
                  } }
                });
              })
            })
          }
        }
        if(!dimension && (index == this.applicationIndex)) {
          List() {
            ForEach(item.permissions, (permission) => {
              ListItem() {
                Row() {
                  Image(permission.icon)
                    .customizeImage(Constants.MANAGEMENT_IMAGE_WIDTH, Constants.MANAGEMENT_IMAGE_HEIGHT)
                    .margin({ right: Constants.MANAGEMENT_IMAGE_MARGIN_RIGHT_RECORD, left: Constants.MANAGEMENT_IMAGE_MARGIN_LEFT })
                  Column() {
                    Row().width(Constants.FULL_WIDTH).height(Constants.TEXT_DECORATION_HEIGHT)
                      .backgroundColor($r("app.color.label_color_lightest"))
                      .margin({ bottom: Constants.LISTITEM_MARGIN_BOTTOM_APPLICATION })
                    Text(permission.label || permission.groupName)
                      .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                      .fontWeight(FontWeight.Medium)
                      .fontColor($r('app.color.label_color'))
                      .lineHeight(Constants.TEXT_LINE_HEIGHT)
                      .margin({ bottom: Constants.TERTIARY_LABEL_MARGIN_BOTTOM })
                    Text(this.strings.visits + permission.count + this.strings.recent_visit + this.getTime(permission.lastTime))
                      .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                      .fontColor($r('app.color.label_color_light'))
                      .lineHeight(Constants.TEXT_SMALL_LINE_HEIGHT)
                  }.alignItems(HorizontalAlign.Start)
                  .height(Constants.FULL_HEIGHT)
                }
              }.height(Constants.LISTITEM_HEIGHT_APPLICATION)
              .onClick(() => {
                router.push({
                  uri: 'pages/application-secondary',
                  params: { routerData: {
                    'bundleName': item.name,
                    'tokenId': item.accessTokenId,
                    'iconId': item.icon,
                    'labelId': item.groupName,
                    'permissions': item.reqUserPermissions,
                    'groupId': item.groupIds
                  } }
                });
              })
            })
          }
        }
      }
    }.padding({ left: dimension ? Constants.LISTITEM_PADDING_LEFT_RECORD : Constants.LISTITEM_PADDING_LEFT,
      right: Constants.LISTITEM_PADDING_RIGHT })
    .margin({ bottom: Constants.LISTITEM_MARGIN_BOTTOM })
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(Constants.BORDER_RADIUS)
  }

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
              backBar( { title: JSON.stringify($r('app.string.permission_access_record')), recordable: false })
            }
            Row() {
              Column() {
                Column() {
                  Stack() {
                    Tabs() {
                      TabContent() {
                        Row() {
                          Column() {
                            Scroll() {
                              Row() {
                                List() {
                                  ForEach(groups, (item, index) => {
                                    this.ListItemLayout(item, index, Constants.PERMISSION)
                                  }, item => item.toString())
                                }.padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                              }.padding({
                                left: Constants.MANAGEMENT_ROW_PADDING_LEFT,
                                right: Constants.MANAGEMENT_ROW_PADDING_RIGHT,
                                top: Constants.MANAGEMENT_ROW_PADDING_TOP
                              })
                            }.scrollBar(BarState.Off)
                          }.width(Constants.FULL_WIDTH)
                        }
                      }.tabBar($r('app.string.authority'))
                      TabContent() {
                        Row() {
                          Column() {
                            Scroll() {
                              Row() {
                                List() {
                                  ForEach(this.appInfos, (item, index) => {
                                    this.ListItemLayout(item, index, Constants.APPLICATION)
                                  }, item => item.toString())
                                }.padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                              }.padding({
                                left: Constants.MANAGEMENT_ROW_PADDING_LEFT,
                                right: Constants.MANAGEMENT_ROW_PADDING_RIGHT,
                                top: Constants.MANAGEMENT_ROW_PADDING_TOP
                              })
                            }.scrollBar(BarState.Off)
                          }.width(Constants.FULL_WIDTH)
                        }
                      }.tabBar($r('app.string.application'))
                    }
                    .barWidth(Constants.BAR_WIDTH)
                    .barMode(BarMode.Fixed)
                  }.height(Constants.FULL_HEIGHT)
                }
              }
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

/**
   * Get time
   * @param {Number} The time stamp
   */
  getTime(time, format='MM月DD日 NNHH:mm') {
    if(this.strings.morning == 'am') { format = 'MM/DD HH:mm NN' }
    let date = new Date(time)
    let config = {
      MM: date.getMonth() + 1,
      DD: date.getDate(),
      NN: date.getHours() >= 12 ? this.strings.afternoon : this.strings.morning,
      HH: date.getHours() >= 12 ? date.getHours() - 12 : date.getHours(),
      mm: date.getMinutes() > 10 ? date.getMinutes() : '0' + date.getMinutes(),
    }

    for(const key in config){
      format = format.replace(key,config[key])
    }
    return format
  }

/**
   * Get app name resource
   * @param {Number} index index of all app permissions array
   * @param {String} bundleName Package names
   */
  updateAppLabel(index, bundleName) {
    Resmgr.getResourceManager(bundleName).then(item => {
      if (index >= this.applicationInfos.length) {
        return;
      }
      var info = this.applicationInfos[index];
      item.getString(info['labelId'], (error, value) => {
        if (value == undefined) {
          info['groupName'] = info.label;
        } else {
          info['groupName'] = value;
        }
      })
    }).catch(error => {
      console.error(TAG + 'Resmgr.getResourceManager failed. Cause: ' + JSON.stringify(error));
    })
  }

/**
   * Get app icon resources
   * @param {Number} index index of all app permissions array
   * @param {String} bundleName Package names
   */
  updateAppIcon(index, bundleName) {
    Resmgr.getResourceManager(bundleName).then(item => {
      if (index >= this.applicationInfos.length) {
        return;
      }
      var info = this.applicationInfos[index];
      item.getMediaBase64(info['iconId'], (error, value) => {
        info['icon'] = value;
      })
    }).catch(error => {
      console.error(TAG + 'Resmgr.getResourceManager failed. Cause: ' + JSON.stringify(error));
    })
  }

  async getApplicationInfo(info) {
    var reqUserPermissions: string[] = [];
    var permissionGroups: any[] = [];
    var acManager = abilityAccessCtrl.createAtManager()
    for (let j = 0; j < info.reqPermissions.length; j++) {
      var permission = info.reqPermissions[j];
      var flag = await acManager.getPermissionFlags(info.appInfo.accessTokenId, permission)
      if(flag == Constants.PRE_AUTHORIZATION_NOT_MODIFIED) {
        continue
      }
      if (userGrantPermissions.indexOf(permission) != -1) {
        reqUserPermissions.push(permission);
      }
    }
    reqUserPermissions.forEach(permission => {
      var group = getPermissionGroup(permission)
      if(!group) {
        console.info(TAG + "permission not find:" + permission)
      }else {
        var exist = permissionGroups.find(permissionGroup => permissionGroup.name == group.name)
        if(!exist) {
          group.count = 0
          group.lastTime = 0
          permissionGroups.push(group)
        }
      }
    })

    let groupIds = [];
    for (let i = 0; i < reqUserPermissions.length; i++) {
      if(groupIds.indexOf(permissionGroupIds[reqUserPermissions[i]]) == -1){
        groupIds.push(permissionGroupIds[reqUserPermissions[i]]);
      }
    }

    info.appInfo.reqUserPermissions = reqUserPermissions
    info.appInfo.permissions = permissionGroups
    info.appInfo.groupIds = groupIds
    this.applicationInfos.push(info.appInfo)
  }

  getApplicationPermissions() {
    bundle.getAllBundleInfo(Constants.PARMETER_BUNDLE_FLAG).then(async allBundleInfo => {
      if (allBundleInfo.length <= 0) {
        console.info(TAG + 'bundle.getAllBundleInfo result.length less than or equal to zero');
        return;
      }
      var infoIndex = 0;
      const this_ = this;
      for (let i = 0; i < allBundleInfo.length; i++) {
        var info = allBundleInfo[i];
        // Filter blank icon icon and text label resources
        try {
          const ret = await bundle.queryAbilityByWant({
            bundleName: info.name,
            action: "action.system.home",
            entities: ["entity.system.home"]
          }, bundle.BundleFlag.GET_ABILITY_INFO_WITH_APPLICATION, Constants.USERID);
        } catch(e) {
          continue;
        }

        if (noNeedDisplayApp.indexOf(info.name) != -1) {
          continue;
        }
        await this.getApplicationInfo(info);
        this.updateAppLabel(infoIndex, info.name);
        this.updateAppIcon(infoIndex, info.name);
        infoIndex ++;
      }
      setTimeout(function(){ this_.appInfos = this_.applicationInfos }, 10)
    })
  }

  getRecords(tokenId, index) {
    let request = {
      "tokenId": tokenId,
      "isRemote": false,
      "permissionNames": [],
      "beginTime": 0,
      "endTime": 0,
      "flag": 1
    }
    privacyManager.getPermissionUsedRecords(request).then(records => {
      console.info(TAG + "records: " + JSON.stringify(records.bundleRecords))
      if(records.bundleRecords.length) {
        records.bundleRecords.permissionRecords.forEach(permissionRecord => {
          this.appInfos[index].permissions.forEach(group => {
            if(group.permissions.includes(permissionRecord.permissionName)) {
              group.count += permissionRecord.accessCount
              group.count += permissionRecord.rejectCount
              var lastTime = permissionRecord.lastAccessTime > permissionRecord.lastRejectTime
                ? permissionRecord.lastAccessTime : permissionRecord.lastRejectTime
              lastTime > group.lastTime ? group.lastTime = lastTime : ''
            }
          })
        })
      }
    }).catch(error => {
      console.error(TAG + 'getPermissionUsedRecords failed. Cause: ' + JSON.stringify(error));
    })
  }

  getStrings() {
    Resmgr.getResourceManager(Constants.BUNDLE_NAME).then(item => {
      item.getString($r("app.string.visits").id, (err, val) => {
        this.strings.visits = val
      })
      item.getString($r("app.string.recent_visit").id, (err, val) => {
        this.strings.recent_visit = val
      })
      item.getString($r("app.string.morning").id, (err, val) => {
        this.strings.morning = val
      })
      item.getString($r("app.string.afternoon").id, (err, val) => {
        this.strings.afternoon = val
      })
    }).catch(error => {
      console.error(TAG + 'Resmgr.getResourceManager failed. Cause: ' + JSON.stringify(error));
    })
  }

  aboutToAppear() {
    this.getApplicationPermissions()
    this.getStrings()
  }
}
