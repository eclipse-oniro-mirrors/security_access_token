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
import Resmgr from '@ohos.resourceManager';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import { groups, userGrantPermissions, permissionGroupPermissions, noNeedDisplayApp } from "../common/model/permissionGroup.ets";
import { permissionGroups, permissionPermissionGroup, permissionGroupIds } from "../common/model/permissionGroup.ets";
import { makePy } from "../common/utils/utils.ets";
import Constants from '../common/utils/constant.ets';

var TAG = 'PermissionManager_MainAbility:'

@Extend(Image) function customizeImage(width: number, height: number) {
  .objectFit(ImageFit.Contain)
  .width(width)
  .height(height)
};

interface applicationPermissions {
  'bundleName': string,
  'iconId': string,
  'permissions': string[],
  'labelId': string,
  'tokenId': number,
  'groupId': number[]
};

interface permissionApplications {
  'permission': string,
  'groupName': string,
  'bundleNames': string[],
  'icon': string
};

interface groupPermission {
  'group': string,
  'permissions': string[],
  'groupName': string,
  'icon': string,
  'isShow':boolean
};

let bundleInfosList: any[] = []; // Permission information array

@Entry
@Component
struct authorityManagementPage {
  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Image(item.icon)
                .customizeImage(Constants.MANAGEMENT_IMAGE_WIDTH, Constants.MANAGEMENT_IMAGE_HEIGHT)
                .margin({ right: Constants.MANAGEMENT_IMAGE_MARGIN_RIGHT })
              Text(item.groupName)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.label_color'))
                .flexGrow(Constants.FLEX_GROW)
              Image($r('app.media.rightarrow'))
                .customizeImage(Constants.IMAGE_WIDTH, Constants.IMAGE_HEIGHT)
            }
            .width(Constants.FULL_WIDTH)
            .height(Constants.MANAGEMENT_ROW_HEIGHT)
          }
          if (!index) {
            Row() {
              Column()
                .backgroundColor($r('app.color.text_decoration_color'))
                .width(Constants.MANAGEMENT_TEXT_DECORATION_WIDTH)
                .height(Constants.TEXT_DECORATION_HEIGHT)
                .margin({ left: Constants.MANAGEMENT_TEXT_DECORATION_MARGIN_LEFT })
            }
          }
        }.onClick(() => {
          if (item.groupName === '其他权限' || item.groupName === '电话' || item.groupName === '通讯录' || item.groupName === '信息'
          || item.groupName === '通话记录' || item.groupName === '日历') {
            router.push({
              uri: 'pages/authority-secondary',
              params: { routerData: this.allPermissionApplications, backTitle: item.groupName }
            })
          } else {
            var dataList = this.allPermissionApplications.filter((ele) => {
              return ele.groupName === item.group
            })

            router.push({
              uri: 'pages/authority-tertiary-groups',
              params: { routerData: dataList, backTitle: item.groupName  }
            })
          }
        })
      }
    }.padding({ left: Constants.LISTITEM_PADDING_LEFT, right: Constants.LISTITEM_PADDING_RIGHT })
  }

  @State allApplicationPermissions: applicationPermissions[] = []; // All permissions apply
  @State allPermissions: string[] = []; // All permissions
  @State allSystemPermissions: string[] = []; // All system permissions
  @State allUserPermissions: string[] = []; // All user rights
  @State allPermissionApplications: permissionApplications [] = [] // All app permissions
  @State allGroups: string[] = [] // All groups
  @State allGroupPermission: groupPermission[] = [] // All group permissions

  /**
   * Convert the permission array into key, value key-value objects for easy sorting
   * @param {Array} order User rights
   * @return {Object} return the processed object
   */
  orderDict(order) {
    let result = {};
    for (let i = 0; i < order.length; i++) {
      let key = order[i];
      result[key] = i;
    }
    return result;
  }

  /**
   * Compare and sort the permission array according to the permission key value
   * @param {String} prop Sort by permission
   * @param {Object} orderSort objects to be sorted
   * @return {Array} Returns a sorted array of permissions
   */
  compare(prop, orderSort) {
    return function(a, b) {
      let aSortValue = orderSort[a[prop]];
      let bSortValue = orderSort[b[prop]];
      if (aSortValue == undefined) {
        throw new Error('当前的字段不在排序列表里：' + a[prop]);
      }
      if (bSortValue == undefined) {
        throw new Error('当前的字段不在排序列表里：' + b[prop]);
      }
      return aSortValue - bSortValue;
    }
  }

  /**
   * Get all app permission information
   * @param {Array} allPermissions All permissions
   * @param {Object} allApplicationPermissions All app permissions
   */
  getAllBundlePermissions(allPermissions: string[], allApplicationPermissions: applicationPermissions[]) {
    bundle.getAllBundleInfo(Constants.PARMETER_BUNDLE_FLAG).then(async(res) => {
      const bundleInfos = res;
      var count = bundleInfos.length;
      if (count <= 0) {
        console.info(TAG + 'bundle.getAllBundleInfo result.length less than or equal to zero');
        return;
      }
      var infoIndex = 0;
      for (let i = 0; i < count; i++) {
        var info = bundleInfos[i];
        // Filter blank icon icon and text label resources
        try {
          const ret = await bundle.queryAbilityByWant({
            bundleName: info.name,
            action: "action.system.home",
            entities: ["entity.system.home"]
          }, bundle.BundleFlag.GET_ABILITY_INFO_WITH_APPLICATION, Constants.USERID);
        } catch(e) {
          console.log(TAG + 'queryAbilityByWant catch error: ' + JSON.stringify(e))
          continue;
        }

        if (noNeedDisplayApp.indexOf(info.name) != -1) {
          continue;
        }
        await this.deduplicationPermissions(info, allPermissions, allApplicationPermissions);
        this.updateAppLabel(infoIndex, info.name, info.appInfo.label);
        this.updateAppIcon(infoIndex, info.name);
        infoIndex = infoIndex + 1;
      }
      this.getAllPermissionApplications();
      let orderSort = this.orderDict(userGrantPermissions);
      this.allPermissionApplications.sort(this.compare('permission', orderSort));
      this.getAllGroupPermission();
      bundleInfosList = this.allApplicationPermissions;
      bundleInfosList.forEach((item) => {
        if (!isNaN(item.labelId)) {
          item.alphabeticalIndex = '';
        } else {
          item.alphabeticalIndex = makePy(item.labelId)[0].slice(0, 1); // Get the first letter in the returned initials array
        }
      })
    })
      .catch((error) => {
        console.error(TAG + 'bundle.getAllBundleInfo failed. Cause: ' + JSON.stringify(error));
      })
  }

  /**
   * Get the corresponding permission group id according to the permission
   * @param {String} permission app name id
   * @return {Number} groupId
   */
  getPermissionGroupByPermission(permission: string) {
    for (let i = 0; i < permissionGroups.length; i++) {
      if (permissionGroups[i].permissionName == permission) {
        return groups[permissionGroups[i].groupId];
      }
    }
  }

  /**
   * Get all app permission information
   */
  getAllPermissionApplications() {
    const this_ = this;
    var leng = this_.allPermissions.length;
    if (leng > 0) {
      for (let i = 0; i < leng; i++) {
        if (userGrantPermissions.indexOf(this_.allPermissions[i]) == -1) {
          this_.allSystemPermissions.push(this_.allPermissions[i]);
        } else {
          this_.allUserPermissions.push(this_.allPermissions[i]);
        }
      }
    }
    for (let i = 0; i < this_.allUserPermissions.length; i++) {
      var permissionGroup = this_.getPermissionGroupByPermission(this_.allUserPermissions[i]);
      var icon: string = permissionGroup.icon;
      var bundleNames: string[] = [];
      for (let j = 0; j < this_.allApplicationPermissions.length; j++) {
        if (this_.allApplicationPermissions[j].permissions.indexOf(this_.allUserPermissions[i]) != -1) {
          bundleNames.push(this_.allApplicationPermissions[j].bundleName);
        }
      }
      var pa: permissionApplications = {
        'permission': this_.allUserPermissions[i],
        'groupName': permissionGroup.name,
        'bundleNames': bundleNames,
        'icon': icon
      };
      this_.allPermissionApplications.push(pa);
    }
  }

  /**
   * Get permission group information
   */
  getAllGroupPermission() {
    const this_ = this;
    var temp1 = [];
    temp1 = ["LOCATION","CAMERA","MICROPHONE","MEDIA","CALENDAR","SPORT","HEALTH"];
    groups.forEach((item) => {
      if (temp1.indexOf(item.name) > -1) {
        var gp: groupPermission = {
          "group": item.name,
          "permissions": item.permissions,
          'groupName': item.groupName,
          'icon': item.icon,
          'isShow': item.isShow
        };
        this_.allGroupPermission.push(gp);
      }
    })
    let temp2 = [];
    groups.forEach((item) => {
      if (item.isShow && temp1.indexOf(item.name) === -1) {
        var gp: groupPermission = {
          "group": item.name,
          "permissions": item.permissions,
          'groupName': item.groupName,
          'icon': item.icon,
          'isShow': item.isShow
        };
        temp2.push(item.name);
        this_.allGroupPermission.push(gp);
      }
    })
    for (let i = 0; i < this_.allPermissionApplications.length; i++) {
        if (this_.allGroups.indexOf(this_.allPermissionApplications[i].groupName) == -1
        && temp1.indexOf(this_.allPermissionApplications[i].groupName) == -1) {
          this_.allGroups.push(this_.allPermissionApplications[i].groupName);
        }
    }
    // Permission layout
    var temp = this_.allGroups;
    temp = temp.filter(function(item) {
      return temp1.indexOf(item) == -1 && temp2.indexOf(item) == -1;
    });
    if (temp.indexOf("OTHER") > -1) {
      temp.splice(temp.indexOf("OTHER"),1);
      temp.push("OTHER");
    }else {
      temp.push("OTHER");
    }
    this_.allGroups = temp;
    for (let i = 0; i < this_.allGroups.length; i++) {
      var permissions: string[] = permissionGroupPermissions[this_.allGroups[i]];
      var gp: groupPermission = {
        "group": this_.allGroups[i],
        "permissions": permissions,
        'groupName': '',
        'icon': '',
        'isShow': false
      };
      this_.allGroupPermission.push(gp);
    }
    this.allGroupPermission.forEach((ele) => {
      groups.forEach((item) => {
        if (ele.group === item.name) {
          ele.groupName = item.groupName;
          ele.icon = item.icon;
          ele.isShow = item.isShow;
        }
      });
    })
  }

  /**
   * Deduplicate permission information and permission group information
   * @param {Object} info bundleInfos Application Information
   * @param {Array} allPermissions All permissions
   * @param {Array} allApplicationPermissions All permissions apply
   */
  async deduplicationPermissions(info, allPermissions, allApplicationPermissions) {
    var reqPermissionsLen = info.reqPermissions.length;
    var reqUserPermissions: string[] = [];
    var acManager = abilityAccessCtrl.createAtManager()
    if (reqPermissionsLen > 0) {
      for (let j = 0; j < info.reqPermissions.length; j++) {
        var permission = info.reqPermissions[j];
        var flag = await acManager.getPermissionFlags(info.appInfo.accessTokenId, permission)
        if(flag == Constants.PRE_AUTHORIZATION_NOT_MODIFIED) {
          continue
        }
        if (allPermissions.indexOf(permission) == -1) {
          allPermissions.push(permission);
        }
        if (userGrantPermissions.indexOf(permission) != -1) {
          reqUserPermissions.push(permission);
        }
      }
    }
    let dePermissions = [];
    let groupIds = [];
    for (let i = 0; i < reqUserPermissions.length; i++) {
      if(dePermissions.indexOf(permissionPermissionGroup[reqUserPermissions[i]]) == -1){
        dePermissions.push(permissionPermissionGroup[reqUserPermissions[i]]);
      }
      if(groupIds.indexOf(permissionGroupIds[reqUserPermissions[i]]) == -1){
        groupIds.push(permissionGroupIds[reqUserPermissions[i]]);
      }
    }

    // adapt different api
    if (info.compatibleVersion >= Constants.API_VERSION_SUPPORT_STAGE) {
      info.appInfo.iconId = info.hapModuleInfos[0].abilityInfo[0].iconId;
    }

    var ap: applicationPermissions = {
      'bundleName': info.name,
      'tokenId': info.appInfo.accessTokenId,
      'iconId': info.appInfo.iconId,
      'labelId': info.appInfo.labelId,
      'permissions': reqUserPermissions,
      'groupId': groupIds
    };
    allApplicationPermissions.push(ap);
  }

  /**
   * Get app name resource
   * @param {Number} index index of all app permissions array
   * @param {String} bundleName Package names
   * @param {String} labelName Application Name
   */
  updateAppLabel(index, bundleName, labelName) {
    Resmgr.getResourceManager(bundleName).then(item => {
      if (index >= this.allApplicationPermissions.length) {
        return;
      }
      var info = this.allApplicationPermissions[index];
      item.getString(info['labelId'], (error, value) => {
        if (value == undefined) {
          info['labelId'] = labelName;
        } else {
          info['labelId'] = value;
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
      if (index >= this.allApplicationPermissions.length) {
        return;
      }
      var info = this.allApplicationPermissions[index];
      item.getMediaBase64(info['iconId'], (error, value) => {
        info['iconId'] = value;
      })
    }).catch(error => {
      console.error(TAG + 'Resmgr.getResourceManager failed. Cause: ' + JSON.stringify(error));
    })
  }

  /**
   * Lifecycle function, executed when the page is initialized
   */
  aboutToAppear() {
    console.log(TAG + 'on aboutToAppear, version 1.01');
    this.getAllBundlePermissions(this.allPermissions, this.allApplicationPermissions);
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
              backBar( { title: JSON.stringify($r('app.string.authority_management')) })
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
                                  if(this.allGroupPermission.length) {
                                    List() {
                                      ForEach(this.allGroupPermission.slice(Constants.SLICE_START,
                                        this.allGroupPermission.length - 1), (item) => {
                                        this.ListItemLayout(item, Constants.SLICE_START_INDEX)
                                      }, item => item.toString())
                                      ForEach(this.allGroupPermission.slice(Constants.SLICE_END), (item, index) => {
                                        this.ListItemLayout(item, Constants.SLICE_END_INDEX)
                                      }, item => item.toString())
                                    }.backgroundColor($r('app.color.default_background_color'))
                                    .borderRadius(Constants.BORDER_RADIUS)
                                    .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                                  }
                                }.padding({
                                  left: Constants.MANAGEMENT_ROW_PADDING_LEFT,
                                  right: Constants.MANAGEMENT_ROW_PADDING_RIGHT,
                                  top: Constants.MANAGEMENT_ROW_PADDING_TOP
                                })
                                .height(Constants.FULL_HEIGHT)
                              }
                            }.width(Constants.FULL_WIDTH)
                          }
                      }.tabBar($r('app.string.authority'))
                      TabContent() {
                        applicationItem({
                          applicationItem: bundleInfosList,
                          oldApplicationItem: bundleInfosList
                        })
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
}

@Component
struct applicationItem {
  @State applicationItem: any[] = bundleInfosList // application info array
  @State oldApplicationItem: any[] = bundleInfosList // Original application information array
  @State searchResult: boolean = true // search results

  @Builder ListItemLayout(item, index) {
    ListItem() {
      Row() {
        Column() {
          Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center }) {
            Row() {
              Image(item.iconId)
                .customizeImage(Constants.APPLICATION_IMAGE_WIDTH, Constants.APPLICATION_IMAGE_HEIGHT)
                .margin({ right: Constants.APPLICATION_IMAGE_MARGIN_RIGHT })
              Text(item.labelId)
                .fontSize(Constants.TEXT_MIDDLE_FONT_SIZE)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.label_color'))
                .flexGrow(Constants.FLEX_GROW)
              Text(item.groupId.length + '项权限')
                .fontSize(Constants.TEXT_SMAL_FONT_SIZE)
                .fontColor($r('app.color.label_color_lighter'))
                .margin({ right: Constants.APPLICATION_TEXT_MARGIN_RIGHT })
              Image($r('app.media.rightarrow'))
                .customizeImage(Constants.IMAGE_WIDTH, Constants.IMAGE_HEIGHT)
            }
            .width(Constants.FULL_WIDTH)
            .height(Constants.AUTHORITY_ROW_HEIGHT)
            .constraintSize({ minHeight: Constants.AUTHORITY_CONSTRAINTSIZE_MINHEIGHT })
            .padding({ left: Constants.APPLICATION_LIST_PADDING_LEFT, right: Constants.APPLICATION_LIST_PADDING_RIGHT })
          }
          if (!index) {
            Row() {
              Column()
                .backgroundColor($r('app.color.text_decoration_color'))
                .width(Constants.APPLICATION_TEXT_DECORATION_WIDTH)
                .height(Constants.TEXT_DECORATION_HEIGHT)
                .margin({ left: Constants.APPLICATION_TEXT_DECORATION_MARGIN_LEFT })
            }
          }
        }.onClick(() => {
          router.push({
            uri: 'pages/application-secondary',
            params: { routerData: item }
          });
        })
      }
    }.padding({
      left: Constants.APPLICATION_LISTITEM_PADDING_LEFT,
      right: Constants.APPLICATION_LISTITEM_PADDING_RIGHT
    })
  }

  build() {
    Column() {
      Row() {
        textInput({
          placeholder: $r('app.string.textInput_placeholder'),
          applicationItem: $applicationItem,
          oldApplicationItem: $oldApplicationItem,
          searchResult: $searchResult
        })
      }.padding({
        left: Constants.APPLICATION_TEXTINPUT_PADDING_LEFT,
        top: Constants.APPLICATION_TEXTINPUT_PADDING_TOP,
        right: Constants.APPLICATION_TEXTINPUT_PADDING_RIGHT
      })
      Scroll() {
        Row() {
          Flex({ alignItems: ItemAlign.Start }) {
            Column() {
              if (!this.applicationItem.length) {
                if (this.searchResult) {
                  Row() {
                    List() {
                      ForEach(this.applicationItem.slice(Constants.SLICE_START, this.applicationItem.length - 1),
                      (item) => {
                        this.ListItemLayout(item, Constants.SLICE_START_INDEX)
                      }, item => item.toString())
                      ForEach(this.applicationItem.slice(Constants.SLICE_END), (item, index) => {
                        this.ListItemLayout(item, Constants.SLICE_END_INDEX)
                      }, item => item.toString())
                    }.backgroundColor($r('app.color.default_background_color')).borderRadius(Constants.BORDER_RADIUS)
                  }.margin({ top: Constants.MANAGEMENT_ROW_MARGIN_TOP })
                   .padding({ left: Constants.MANAGEMENT_ROW_PADDING_LEFT })
                } else {
                  Row() {
                    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
                      Image($r('app.media.searchnoresult'))
                        .customizeImage(Constants.SEARCHNORESULT_IMAGE_WIDTH, Constants.SEARCHNORESULT_IMAGE_HEIGHT)
                    }
                  }.margin({ top: Constants.MANAGEMENT_ROW_MARGIN_TOP })
                  .padding({ left: Constants.MANAGEMENT_ROW_PADDING_LEFT })
                }
              } else {
                Row() {
                  List() {
                    ForEach(this.applicationItem.slice(Constants.SLICE_START, this.applicationItem.length - 1),
                    (item) => {
                      this.ListItemLayout(item, Constants.SLICE_START_INDEX)
                    }, item => item.toString())
                    ForEach(this.applicationItem.slice(Constants.SLICE_END), (item, index) => {
                      this.ListItemLayout(item, Constants.SLICE_END_INDEX)
                    }, item => item.toString())
                  }.backgroundColor($r('app.color.default_background_color'))
                   .borderRadius(Constants.BORDER_RADIUS)
                   .padding({ top: Constants.LIST_PADDING_TOP, bottom: Constants.LIST_PADDING_BOTTOM })
                }.margin({ top: Constants.MANAGEMENT_ROW_MARGIN_TOP })
                .padding({ left: Constants.MANAGEMENT_ROW_PADDING_LEFT })
              }
            }
            .backgroundColor($r('app.color.background_color'))
            .height(Constants.APPLICATION_COLUMN_HEIGHT)
            Column() {
              alphabetIndexerComponent({ applicationItem: $applicationItem, oldApplicationItem: $oldApplicationItem })
            }
            .margin({ top: Constants.APPLICATION_ALPHABETINDEX_MARGIN_TOP })
            .width(Constants.APPLICATION_ALPHABETINDEX_WIDTH)
          }
        }
      }
    }
  }
}
