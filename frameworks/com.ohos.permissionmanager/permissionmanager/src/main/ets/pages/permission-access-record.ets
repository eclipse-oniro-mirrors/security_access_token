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
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import privacyManager from '@ohos.privacyManager'
import { backBar } from "../common/components/backBar";
import Constants from '../common/utils/constant';
import { noNeedDisplayApp, userGrantPermissions, permissionGroupIds } from "../common/model/permissionGroup";
import { getPermissionGroup } from '../common/utils/utils'

var TAG = 'PermissionManager_MainAbility:'

@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
};

@Entry
@Component
struct permissionRecordPage {
  @State groups: any[] = []
  @State applicationInfos: any[] = []
  @State permissionApplications: any[] = []
  @State permissionIndex: number = -1
  @State applicationIndex: number = -1
  @State strings: any = {}
  @State currentIndex: number = 0
  @Builder TabBuilder(index: number) {
    Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
      Text(index ? $r('app.string.application') : $r('app.string.authority'))
        .fontColor(this.currentIndex == index ? $r('app.color.button_color') : $r('app.color.label_color'))
        .fontWeight(this.currentIndex == index ? FontWeight.Bold : FontWeight.Regular)
        .lineHeight(Constants.TEXT_LINE_HEIGHT)
      if(this.currentIndex == index) {
        Row().width(Constants.FULL_WIDTH).height(Constants.TAB_DECORATION_HEIGHT)
          .backgroundColor($r('app.color.button_color'))
          .position({ y: Constants.TAB_DECORATION_POSITION_Y })
      }
    }.height(Constants.TAB_HEIGHT)
  }

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
                  Text(this.strings.visits + item.sum)
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
            this.permissionApplications = this.applicationInfos.filter(appInfo => {
              return appInfo.groupNames.includes(item.groupName)
            })
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
                    Text(this.strings.visits + this.getAppRecords(permissionApplication, item.groupName, true) +
                        this.strings.recent_visit + this.getTime(this.getAppRecords(permissionApplication, item.groupName, false)))
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
                    Text(permission.groupName)
                      .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                      .fontWeight(FontWeight.Medium)
                      .fontColor($r('app.color.label_color'))
                      .lineHeight(Constants.TEXT_LINE_HEIGHT)
                      .margin({ bottom: Constants.TERTIARY_LABEL_MARGIN_BOTTOM })
                    Text(this.strings.visits + permission['count' + item.accessTokenId]
                        + this.strings.recent_visit + this.getTime(permission['lastTime' + item.accessTokenId]))
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
    }.padding({ left: Constants.DEFAULT_PADDING_START, right: Constants.DEFAULT_PADDING_END,
      top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
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
                  Flex({ justifyContent: FlexAlign.Start }) {
                    Text($r('app.string.record_time_limit'))
                      .margin({ left: Constants.BACKBAR_IMAGE_MARGIN_LEFT })
                      .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                      .fontColor($r('app.color.label_color_light'))
                      .lineHeight(Constants.SUBTITLE_LINE_HEIGHT)
                  }.constraintSize({ minHeight: Constants.SUBTITLE_MIN_HEIGHT })
                  .padding({ top: Constants.SUBTITLE_PADDING_TOP, bottom: Constants.SUBTITLE_PADDING_BOTTOM })
                  if(this.groups.length) {
                    Stack() {
                      Tabs() {
                        TabContent() {
                          Row() {
                            Column() {
                              Scroll() {
                                Row() {
                                  List() {
                                    ForEach(this.groups, (item, index) => {
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
                        }.tabBar(this.TabBuilder(0))
                        TabContent() {
                          Row() {
                            Column() {
                              Scroll() {
                                Row() {
                                  List() {
                                    ForEach(this.applicationInfos, (item, index) => {
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
                        }.tabBar(this.TabBuilder(1))
                      }
                      .barWidth(Constants.BAR_WIDTH)
                      .barMode(BarMode.Fixed)
                      .onChange((index) => {
                        this.currentIndex = index
                      })
                    }.height(Constants.FULL_HEIGHT)
                  }else {
                    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center, direction: FlexDirection.Column }) {
                      Image($r('app.media.noRecord'))
                        .customizeImage(Constants.NORECORD_IMAGE_WIDTH, Constants.NORECORD_IMAGE_HEIGHT)
                        .margin({ left: Constants.NORECORD_IMAGE_MARGIN_LEFT })
                      Text($r('app.string.no_record')).margin({ top: Constants.DIALOG_REQ_MARGIN_TOP })
                        .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                        .fontColor($r('app.color.label_color_light'))
                    }.width(Constants.FULL_WIDTH).height(Constants.FULL_HEIGHT)
                    .padding({ bottom: Constants.RECORD_PADDING_BOTTOM })
                  }
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
    let date = new Date(time * 1000)
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
   * Get application record info
   * @param {Object} application info
   * @param {String} groupName
   * @param {Boolean} true: count, false: lastTime
   */
  getAppRecords(appInfo, groupName, option) {
    var record = appInfo.permissions.filter(permission => {
      return permission.groupName == groupName
    })
    return option ? record[0]['count' + appInfo.accessTokenId] : record[0]['lastTime' + appInfo.accessTokenId]
  }

  getStrings() {
    globalThis.context.resourceManager.getString($r("app.string.visits").id, (err, val) => {
      this.strings.visits = val
    })
    globalThis.context.resourceManager.getString($r("app.string.recent_visit").id, (err, val) => {
      this.strings.recent_visit = val
    })
    globalThis.context.resourceManager.getString($r("app.string.morning").id, (err, val) => {
      this.strings.morning = val
    })
    globalThis.context.resourceManager.getString($r("app.string.afternoon").id, (err, val) => {
      this.strings.afternoon = val
    })
  }

  getInfo(record, sortFlag) {
    bundle.getBundleInfo(record.bundleName, Constants.PARMETER_BUNDLE_FLAG).then(async info => {
      var reqUserPermissions: string[] = [];
      var reqUserRecords: any[] = [];
      var permissionGroups: any[] = [];
      var acManager = abilityAccessCtrl.createAtManager()
      var appInfo: any = {}
      for (let j = 0; j < record.permissionRecords.length; j++) {
        var permission = record.permissionRecords[j].permissionName;
        var flag = await acManager.getPermissionFlags(info.appInfo.accessTokenId, permission)
        if(flag == Constants.PRE_AUTHORIZATION_NOT_MODIFIED) {
          continue
        }
        if (userGrantPermissions.indexOf(permission) != -1) {
          reqUserRecords.push(record.permissionRecords[j])
        }
      }
      for (let k = 0; k < info.reqPermissions.length; k++) {
        var reqPermission = info.reqPermissions[k];
        var reqFlag = await acManager.getPermissionFlags(info.appInfo.accessTokenId, reqPermission)
        if(reqFlag == Constants.PRE_AUTHORIZATION_NOT_MODIFIED) {
          continue
        }
        if (userGrantPermissions.indexOf(reqPermission) != -1) {
          reqUserPermissions.push(reqPermission);
        }
      }

      let groupNames = [];
      let appLastTime = 0;
      reqUserRecords.forEach(reqUserRecord => {
        var group = getPermissionGroup(reqUserRecord.permissionName)
        if(!group) {
          console.info(TAG + "permission not find:" + reqUserRecord.permissionName)
        }else {
          var existing = permissionGroups.find(permissionGroup => permissionGroup.name == group.name)
          var lastTime = reqUserRecord.lastAccessTime
          lastTime > appLastTime ? appLastTime = lastTime : ''
          if(!existing) {
            group['count' + record.tokenId] = reqUserRecord.accessCount
            group['lastTime' + record.tokenId] = lastTime
            permissionGroups.push(group)
            groupNames.push(group.groupName)
          }else {
            existing['count' + record.tokenId] += reqUserRecord.accessCount
            lastTime > existing['lastTime' + record.tokenId] ? existing['lastTime' + record.tokenId] = lastTime : ''
          }
        }
      })

      let groupIds = [];
      for (let i = 0; i < reqUserPermissions.length; i++) {
        if(groupIds.indexOf(permissionGroupIds[reqUserPermissions[i]]) == -1){
          groupIds.push(permissionGroupIds[reqUserPermissions[i]]);
        }
      }

      let  context = globalThis.context.createBundleContext(info.name)
      await context.resourceManager.getString(info.appInfo.labelId, (error, value) => {
        if (value == undefined) {
          appInfo.groupName = info.appInfo.label;
        } else {
          appInfo.groupName = value;
        }
      })

      await context.resourceManager.getMediaBase64(info.appInfo.iconId, (error, value) => {
        appInfo.icon = value;
      })

      appInfo.name = info.appInfo.name
      appInfo.accessTokenId = info.appInfo.accessTokenId
      appInfo.reqUserPermissions = reqUserPermissions
      appInfo.permissions = permissionGroups
      appInfo.groupNames = groupNames
      appInfo.groupIds = groupIds
      appInfo.appLastTime = appLastTime
      this.applicationInfos.push(appInfo)
      if(sortFlag) {
        var appInfos: any[] = []
        this.applicationInfos.forEach(item => { appInfos.push(item) })
        appInfos.sort((a, b) => { return b.appLastTime - a.appLastTime })
        this.applicationInfos = appInfos
      }
    })
  }

  getAllRecords() {
    let request = {
      "tokenId": 0,
      "isRemote": false,
      "deviceId": '',
      "bundleName": '',
      "permissionNames": [],
      "beginTime": 0,
      "endTime": 0,
      "flag": 1
    }
    privacyManager.getPermissionUsedRecords(request).then(async records => {
      console.info(TAG + "records: " + JSON.stringify(records.bundleRecords))
      var groupArray: any[] = []
      for (let i = 0; i < records.bundleRecords.length; i++) {
        var record = records.bundleRecords[i]
        try {
          const ret = await bundle.queryAbilityByWant({
            bundleName: record.bundleName,
            action: "action.system.home",
            entities: ["entity.system.home"]
          }, bundle.BundleFlag.GET_ABILITY_INFO_WITH_APPLICATION, Constants.USERID);
        } catch(e) {
          continue;
        }
        if (noNeedDisplayApp.indexOf(record.bundleName) != -1) {
          continue;
        }
        console.info(TAG + "record: " + JSON.stringify(record))
        this.getInfo(record, (i + 1) == records.bundleRecords.length)

        record.permissionRecords.forEach(permissionRecord => {
          var group = getPermissionGroup(permissionRecord.permissionName)
          if(group) {
            var exist = groupArray.find(permissionGroup => permissionGroup.name == group.name)
            var lastTime = permissionRecord.lastAccessTime
            if(!exist) {
              group.sum = permissionRecord.accessCount
              group.recentVisit = lastTime
              groupArray.push(group)
            }else {
              exist.sum += permissionRecord.accessCount
              lastTime > exist.recentVisit ? exist.recentVisit = lastTime : ''
            }
          }
        })
      }
      groupArray.sort((a, b) => { return b.recentVisit - a.recentVisit })
      this.groups = groupArray
    })
  }

  aboutToAppear() {
    this.getStrings()
    this.getAllRecords()
  }
}
