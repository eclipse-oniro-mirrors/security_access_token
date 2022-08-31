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

import Constants from '../utils/constant';

@Extend(Button) function locationButton() {
  .backgroundColor($r('app.color.default_background_color'))
  .fontWeight(FontWeight.Medium)
  .fontSize(Constants.TEXT_SMALLER_FONT_SIZE)
  .height(Constants.LOCATION_BUTTON_HEIGHT)
  .width(Constants.LOCATION_BUTTON_WIDTH)
  .borderRadius(Constants.LOCATION_BUTTON_RADIUS)
  .position({ x: Constants.LOCATION_BUTTON_POSITION_X, y: Constants.LOCATION_BUTTON_POSITION_Y })
}

@Component
export struct LocationCanvas {
  @Link locationFlag: any

  build() {
    Column() {
      Image($r('app.media.img_location_map'))
        .width(Constants.FULL_WIDTH)
        .height(Constants.FULL_HEIGHT)
        .scale({ x:  ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE))
          ? Constants.LOCATION_CANVAS_ZOOM_SCALE : Constants.LOCATION_CANVAS_INITIAL_SCALE,
          y: ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE))
            ? Constants.LOCATION_CANVAS_ZOOM_SCALE : Constants.LOCATION_CANVAS_INITIAL_SCALE })
        .animation({
          duration: Constants.LOCATION_ANIMATION_DURATION, // Animation duration
          curve: Curve.Smooth, // The animation curve
          playMode: PlayMode.Normal // The animation mode
        })
      Image($r('app.media.ic_public_gps_filled'))
        .fillColor($r('sys.color.ohos_id_color_emphasize'))
        .width(Constants.LOCATION_ICON_WIDTH)
        .height(Constants.LOCATION_ICON_HEIGHT)
        .position({ x: Constants.LOCATION_ICON_POSITION_X, y: Constants.LOCATION_ICON_POSITION_Y })
        .opacity(((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE)) ? 1 : 0)
        .scale({ x: ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE)) ? 1 : 0.8,
        y: ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE)) ? 1 : 0.8 })
        .animation({
          duration: Constants.LOCATION_ANIMATION_DURATION / 2, // Animation duration
          delay: this.locationFlag == Constants.LOCATION_BOTH_PRECISE ? (Constants.LOCATION_ANIMATION_DURATION / 2) : 0,
          curve: Curve.Smooth, // The animation curve
          playMode: PlayMode.Normal // The animation mode
        })
      Circle({ width: Constants.LOCATION_CIRCLE_DIA, height: Constants.LOCATION_CIRCLE_DIA })
        .position({ x: Constants.LOCATION_CIRCLE_POSITION_X, y: Constants.LOCATION_CIRCLE_POSITION_Y })
        .fill($r('app.color.location_circle_color'))
        .fillOpacity(Constants.LOCATION_CIRCLE_OPACITY)
        .stroke($r('app.color.location_circle_color'))
        .scale({ x: ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE)) ? 0 : 1,
          y: ((this.locationFlag == Constants.LOCATION_UPGRADE) || (this.locationFlag == Constants.LOCATION_BOTH_PRECISE)) ? 0 : 1 })
        .animation({
          duration: Constants.LOCATION_ANIMATION_DURATION, // Animation duration
          curve: Curve.Smooth, // The animation curve
          playMode: PlayMode.Normal // The animation mode
        })
      if(this.locationFlag == Constants.LOCATION_BOTH_PRECISE) {
        Button($r('app.string.precise_location_on'))
          .locationButton()
          .fontColor($r('app.color.button_color'))
          .onClick(() => { this.locationFlag = Constants.LOCATION_BOTH_FUZZY })
      }
      if(this.locationFlag == Constants.LOCATION_BOTH_FUZZY) {
        Button($r('app.string.precise_location_off'))
          .locationButton()
          .fontColor($r('app.color.label_color_light'))
          .onClick(() => { this.locationFlag = Constants.LOCATION_BOTH_PRECISE })
      }
    }.width(Constants.FULL_WIDTH)
    .height(Constants.LOCATION_CANVAS_HEIGHT)
    .margin({ top: Constants.LOCATION_CANVAS_MARGIN_TOP, bottom: Constants.LOCATION_CANVAS_MARGIN_BOTTOM })
    .clip(true)
  }
}
