import React, { FC, memo, MouseEvent, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  IconBackward,
  IconChevronLeft,
  IconChevronRight,
  IconCollapse,
  IconExpand,
  IconFastForward,
  IconForward,
  IconFullscreen,
  IconFullscreenExit,
  IconInterpolationAdd,
  IconNext,
  IconPause,
  IconPlay,
  IconPrev,
  IconRewind
} from '../../assets/icons/timeline';
import { Button, ButtonProps } from '../../common/Button/Button';
import { Space } from '../../common/Space/Space';
import { Block, Elem } from '../../utils/bem';
import { isDefined } from '../../utils/utilities';
import { TimelineContext } from './Context';
import './Controls.styl';
import * as SideControls from './SideControls';
import {
  TimelineControlsFormatterOptions,
  TimelineControlsProps,
  TimelineControlsStepHandler,
  TimelineCustomControls,
  TimelineProps,
  TimelineStepFunction
} from './Types';
import { FF_DEV_2715, isFF } from '../../utils/feature-flags';
import { AudioControl } from './Controls/AudioControl';
import { ConfigControl } from './Controls/ConfigControl';
import { TimeDurationControl } from '../TimeDurationControl/TimeDurationControl';
import { IconMenu, IconRectangleTool, LsCollapse, LsPlus } from '../../assets/icons';
import { Dropdown } from '../../common/Dropdown/Dropdown';
import { Menu } from '../../common/Menu/Menu';
import {InputNumber, message} from 'antd';

const positionFromTime = ({ time, fps }: TimelineControlsFormatterOptions) => {
  const roundedFps = Math.round(fps).toString();
  const fpsMs = 1000 / fps;
  const currentSecond = (time * 1000) % 1000;
  const result = Math.round(currentSecond / fpsMs).toString();

  return result.padStart(roundedFps.length, '0');
};

export const Controls: FC<TimelineControlsProps> = memo(({
  regions,
  labels,
  length = 1000,
  position,
  frameRate = 1024,
  playing,
  collapsed,
  duration,
  extraControls,
  fullscreen,
  altHopSize,
  disableFrames,
  allowFullscreen,
  allowViewCollapse,
  onRewind,
  onForward,
  onPlay,
  onPause,
  onCallModel,
  onFullScreenToggle,
  onStepBackward,
  onPositionChange,
  onStepForward,
  onSpeedChange,
  onToggleCollapsed,
  formatPosition,
  toggleVisibility,
  layerVisibility,
  mediaType,
  ...props
}) => {
  const { settings, data: timelineData } = useContext(TimelineContext);
  const [altControlsMode, setAltControlsMode] = useState(false);
  const [configModal, setConfigModal] = useState(false);
  const [audioModal, setAudioModal] = useState(false);
  const [callModelLoading, setCallModelLoading] = useState(false);
  const [callCleanSamCacheLoading, setCallCleanSamCacheLoading] = useState(false);
  const [curCallModelLabel, setCurCallModelLabel] = useState('');
  const [samFrameLength, setSamFrameLength] = useState(100);
  const [startReached, endReached] = [position === 1, position === length];

  const durationFormatted = useMemo(() => {
    return Math.max((length - 1) / frameRate, 0);
  }, [length, frameRate]);

  const currentTime = useMemo(() => {
    return (position - 1) / frameRate;
  }, [position, frameRate]);

  const customControls = useCustomControls(props.customControls);
  const stepHandlerWrapper = (handler: TimelineControlsStepHandler, stepSize?: TimelineStepFunction) => (e: MouseEvent<HTMLButtonElement>) => {
    handler(e, stepSize ?? undefined);
  };

  const handlePlay = useCallback(() => {
    playing ? onPause?.() : onPlay?.();
  }, [playing, onPlay, onPause]);

  const onSetVolumeModal = (e: MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    if (configModal) setConfigModal(false);

    setAudioModal(!audioModal);
  };

  const onSetConfigModal = (e: MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();

    if (audioModal) setAudioModal(false);

    setConfigModal(!configModal);
  };

  const renderControls = () => {
    return (
      <Elem name="group" tag={Space} size="small" style={{ gridAutoColumns: 'auto' }}>
        <ConfigControl
          onSetModal={onSetConfigModal}
          onAmpChange={props.onAmpChange}
          configModal={configModal}
          onSpeedChange={(speed: number) => onSpeedChange?.(speed)}
          speed={props.speed || 0}
          amp={props.amp || 0}
          toggleVisibility={toggleVisibility}
          layerVisibility={layerVisibility}
        />
        <AudioControl
          volume={props.volume || 0}
          onVolumeChange={props.onVolumeChange}
          onSetModal={onSetVolumeModal}
          audioModal={audioModal}
        />

      </Elem>
    );
  };

  /**
   * 获取当前画布中所有绘制的标注box
   * @param {number} frame - 帧位置，默认为当前position
   * @returns {Array} 返回所有标注box的数组，每个box包含 {x, y, width, height, rotation, id, labels, ...}
   */
  const getAllAnnotationBoxes = useCallback((frame?: number) => {
    const videoItem = timelineData?.item;
    const currentFrame = frame ?? position;

    if (!videoItem || !videoItem.regs) {
      return [];
    }

    const boxes = [];

    // 遍历所有区域
    for (const region of videoItem.regs) {
      // 检查区域是否隐藏
      if (region.hidden) {
        continue;
      }

      // 检查区域是否在当前帧的生命周期内
      if (typeof region.isInLifespan === 'function' && !region.isInLifespan(currentFrame)) {
        continue;
      }

      // 获取当前帧的box形状
      if (typeof region.getShape !== 'function') {
        continue;
      }

      const shape = region.getShape(currentFrame);

      if (shape) {
        boxes.push({
          id: region.cleanId || region.id,
          ...shape, // x, y, width, height, rotation
          labels: region.labels || [],
          selected: region.selected || region.inSelection || false,
          region: region, // 保留原始region引用，方便后续操作
        });
      }
    }

    return boxes;
  }, [timelineData, position]);

  const callSamModel = useCallback(async () => {

    const prompts = getAllAnnotationBoxes()
    const videoItem = timelineData?.item;

    if (!videoItem) {
      message.error('无法访问视频对象');
      return;
    }

    if (!videoItem.ref?.current) {
      message.error('视频未加载');
      return;
    }

    try {
      setCallModelLoading(true);

      // start sam inference
      const startSamResp = await fetch("/api/tasks/video_sam_predict", {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: videoItem.store.task.id,
          prompt_frame_index: position,
          prompts: prompts,
          predict_frame_length: samFrameLength
        }),
      })
      if (startSamResp.status !== 200) {
        message.error("failed to call sam predict")
        return
      }
      const startSamRet = await startSamResp.json()
      const data = startSamRet["data"]
      message.success("SAM成功，开始标注结果")

      const startFrame = position;
      const endFrame = Math.min(startFrame + samFrameLength - 1, length);
      const totalFrames = endFrame - startFrame + 1;

      message.info(`正在处理 ${totalFrames} 帧 (${startFrame} - ${endFrame})`);

      // 保存原始帧位置，处理完成后恢复
      const originalFrame = videoItem.frame;

      // 存储每一帧检测到的对象，用于跟踪跨帧的对象
      // 格式: Map<objectId, { area: VideoRegion, label: string }>
      const objectMap = new Map<string, object>();
      let totalRegionsAdded = 0;

      // 删除已有label
      const toRemoveRegions: string[] = []
      videoItem.regs.forEach(region => {
        if (region.sequence.length > 0 && region.sequence[0].frame > startFrame) {
          // label开始于当前帧之后，需要删除防止与sam结果冲突
          toRemoveRegions.push(region.cleanId)
        }
      })
      toRemoveRegions.forEach(id => videoItem.deleteRegion(id))

      // 循环处理每一帧
      for (let frameIndex = 0; frameIndex < totalFrames; frameIndex++) {
        const currentFrame = startFrame + frameIndex + 1;

        // 设置视频到指定帧
        videoItem.setFrame(currentFrame);

        // 等待视频帧加载完成（给视频一点时间 seek 到正确位置）
        await new Promise(resolve => setTimeout(resolve, 50));

        // 获取当前帧的图片
        const { blob: videoImg, size } = await videoItem.ref.current.getCurrentImg();
        const { width: waWidth, height: waHeight, offset } = size;

        if (!videoImg) {
          console.warn(`无法获取第 ${currentFrame} 帧图片，跳过`);
          continue;
        }

        // 示例：假设 SAM 模型返回多个区域的边界框
        // 格式: [{ x, y, width, height, label, objectId? }, ...]
        // objectId 用于跟踪同一对象在不同帧中的位置
        const samResults: Array<{
          x: number;
          y: number;
          width: number;
          height: number;
          label?: string;
          object_id?: string; // 可选的，用于跟踪同一对象
        }> = data[frameIndex]

        // 为当前帧的每个检测结果处理
        for (const box of samResults) {
          // 将像素坐标转换为百分比
          let regionData = {x: box.x, y: box.y, width: box.width, height: box.height}
          if (!box.object_id) {
            continue
          }
          let area = videoItem.findRegion(box.object_id)
          if (area) {
            area.interpolation = false;
            area.removeKeypoint(currentFrame)
            area.addKeypoint(currentFrame, null, regionData);
          } else if (objectMap.has(box.object_id)){
            // get from object map
            area = objectMap.get(box.object_id)
            area.interpolation = false;
            area.removeKeypoint(currentFrame)
            area.addKeypoint(currentFrame, null, regionData);
          } else {
            // 创建新的 region
            area = videoItem.addRegion(regionData, box.label);
            area.interpolation = false;
          }
          objectMap.set(box.object_id, area)
        }

        // 更新进度提示
        if ((frameIndex + 1) % 10 === 0 || frameIndex === totalFrames - 1) {
          message.info(`已处理 ${frameIndex + 1}/${totalFrames} 帧`);
        }
      }
      objectMap.forEach((area) => {
        const sequence = area?.sequence
        sequence[sequence.length - 1].enabled = false
      });
      // 恢复原始帧位置
      videoItem.setFrame(originalFrame);

      message.success("SAM成功")
    } catch (error) {
      console.error('SAM 模型调用失败:', error);
      const errorMessage = error instanceof Error ? error.message : '未知错误';
      message.error('SAM 模型调用失败: ' + errorMessage);
    } finally {
      setCallModelLoading(false);
    }
  }, [timelineData, position, samFrameLength, length, setCallModelLoading]);

  const callSamModelSingle = useCallback(async () => {

    const videoItem = timelineData?.item;

    if (!videoItem) {
      message.error('无法访问视频对象');
      return;
    }
    if (!videoItem.ref?.current) {
      message.error('视频未加载');
      return;
    }

    // get selected region
    const selectedRegions = videoItem.regs.filter((reg: { inSelection: boolean; }) => reg.inSelection)
    if (selectedRegions.length != 1) {
      message.error('请选择一个需要SAM的label');
      return;
    }
    const selectedRegionId = selectedRegions[0].cleanId
    const prompts = getAllAnnotationBoxes().filter(prompt => prompt.id === selectedRegionId)

    try {
      setCallModelLoading(true);

      // start sam inference
      const startSamResp = await fetch("/api/tasks/video_sam_predict_single", {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: videoItem.store.task.id,
          prompt_frame_index: position,
          prompts: prompts,
          is_single_predict: true,
          predict_frame_length: samFrameLength
        }),
      })
      if (startSamResp.status !== 200) {
        message.error("failed to call sam predict")
        return
      }
      const startSamRet = await startSamResp.json()
      const data = startSamRet["data"]
      message.success("SAM成功，开始标注结果")

      const startFrame = position;
      const endFrame = Math.min(startFrame + samFrameLength - 1, length);
      const totalFrames = endFrame - startFrame + 1;

      message.info(`正在处理 ${totalFrames} 帧 (${startFrame} - ${endFrame})`);

      // 保存原始帧位置，处理完成后恢复
      const originalFrame = videoItem.frame;

      // 存储每一帧检测到的对象，用于跟踪跨帧的对象
      // 格式: Map<objectId, { area: VideoRegion, label: string }>
      const objectMap = new Map<string, object>();
      let totalRegionsAdded = 0;

      // 删除已有label
      const toRemoveRegions: string[] = []
      videoItem.regs.forEach(region => {
        if (region.sequence.length > 0 && region.sequence[0].frame > startFrame) {
          // label开始于当前帧之后，需要删除防止与sam结果冲突
          toRemoveRegions.push(region.cleanId)
        }
      })
      toRemoveRegions.forEach(id => videoItem.deleteRegion(id))

      // 循环处理每一帧
      for (let frameIndex = 0; frameIndex < totalFrames; frameIndex++) {
        const currentFrame = startFrame + frameIndex + 1;

        // 设置视频到指定帧
        videoItem.setFrame(currentFrame);

        // 等待视频帧加载完成（给视频一点时间 seek 到正确位置）
        await new Promise(resolve => setTimeout(resolve, 50));

        // 获取当前帧的图片
        const { blob: videoImg, size } = await videoItem.ref.current.getCurrentImg();
        const { width: waWidth, height: waHeight, offset } = size;

        if (!videoImg) {
          console.warn(`无法获取第 ${currentFrame} 帧图片，跳过`);
          continue;
        }

        // 示例：假设 SAM 模型返回多个区域的边界框
        // 格式: [{ x, y, width, height, label, objectId? }, ...]
        // objectId 用于跟踪同一对象在不同帧中的位置
        const samResults: Array<{
          x: number;
          y: number;
          width: number;
          height: number;
          label?: string;
          object_id?: string; // 可选的，用于跟踪同一对象
        }> = data[frameIndex]

        // 为当前帧的每个检测结果处理
        for (const box of samResults) {
          // 将像素坐标转换为百分比
          let regionData = {x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0}
          if (!box.object_id) {
            continue
          }
          let area = videoItem.findRegion(box.object_id)
          if (area) {
            area.interpolation = false;
            area.removeKeypoint(currentFrame)
            area.addKeypoint(currentFrame, null, regionData);
          } else if (objectMap.has(box.object_id)){
            // get from object map
            area = objectMap.get(box.object_id)
            area.interpolation = false;
            area.removeKeypoint(currentFrame)
            area.addKeypoint(currentFrame, null, regionData);
          } else {
            // 创建新的 region
            area = videoItem.addRegion(regionData, box.label);
            area.interpolation = false;
          }
          objectMap.set(box.object_id, area)
        }

        // 更新进度提示
        if ((frameIndex + 1) % 10 === 0 || frameIndex === totalFrames - 1) {
          message.info(`已处理 ${frameIndex + 1}/${totalFrames} 帧`);
        }
      }
      objectMap.forEach((area) => {
        const sequence = area?.sequence
        sequence[sequence.length - 1].enabled = false
      });
      // 恢复原始帧位置
      videoItem.setFrame(originalFrame);

      message.success("SAM成功")
    } catch (error) {
      console.error('SAM 模型调用失败:', error);
      const errorMessage = error instanceof Error ? error.message : '未知错误';
      message.error('SAM 模型调用失败: ' + errorMessage);
    } finally {
      setCallModelLoading(false);
    }
  }, [timelineData, position, samFrameLength, length, setCallModelLoading]);

  const callCleanSamCache = useCallback(async () => {
    const videoItem = timelineData?.item;
    if (!videoItem) {
      message.error('无法访问视频对象');
      return;
    }
    if (!videoItem.ref?.current) {
      message.error('视频未加载');
      return;
    }

    // get selected region
    const selectedRegions = videoItem.regs.filter((reg: { inSelection: boolean; }) => reg.inSelection)
    if (selectedRegions.length != 1) {
      message.error('请选择一个需要clean的label');
      return;
    }
    const selectedRegionId = selectedRegions[0].cleanId
    try {
      setCallCleanSamCacheLoading(true)
      const startSamResp = await fetch("/api/tasks/video_sam_clean_cache", {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: videoItem.store.task.id,
          obj_id: selectedRegionId,
        }),
      })
      if (startSamResp.status !== 200) {
        message.error("failed to clean sam cache")
        return
      }
      const startSamRet = await startSamResp.json()
      message.success("清除当前label的缓存成功")
    } finally {
      setCallCleanSamCacheLoading(false)
    }
  }, [timelineData, position, samFrameLength, length, setCallCleanSamCacheLoading]);

  const closeModalHandler = () => {
    setConfigModal(false);
    setAudioModal(false);
  };

  useEffect(() => {
    const keyboardHandler = (e: KeyboardEvent) => {
      if (!settings?.stepSize) return;
      const altMode = e.key === 'Shift';

      if (e.type === 'keydown' && altMode && !altControlsMode) {
        setAltControlsMode(true);
      } else if (e.type === 'keyup' && altMode && altControlsMode) {
        setAltControlsMode(false);
      }
    };

    document.addEventListener('keydown', keyboardHandler);
    document.addEventListener('keyup', keyboardHandler);
    document.addEventListener('click', closeModalHandler);

    return () => {
      document.removeEventListener('keydown', keyboardHandler);
      document.removeEventListener('keyup', keyboardHandler);
      document.removeEventListener('click', closeModalHandler);
    };
  }, [altControlsMode]);

  useEffect(() => {
    const keyboardHandler = async (e: KeyboardEvent) => {
      if ((e.metaKey || e.altKey) && (e.code === 'KeyM')) {
        if (!curCallModelLabel) {
          message.error('请选择与标注目标label');
          return;
        }
        setCallModelLoading(true);
        await onCallModel?.(curCallModelLabel);
        setCallModelLoading(false);
      }
    };

    document.addEventListener('keydown', keyboardHandler);
    return () => {
      document.removeEventListener('keydown', keyboardHandler);
    };
  }, [curCallModelLabel, position, callModelLoading]);

  const onTimeUpdateChange = (value: number) => {
    onPositionChange(value);
  };

  const dropdownContent = useMemo(() => {
    return (
      <Menu
        size="medium"
        style={{
          width: 200,
          minWidth: 200,
        }}
        selectedKeys={[curCallModelLabel]}
      >
        {labels
          ?.map((item) => {
            return (
              <Menu.Item name={item.value || item.name} key={item.value || item.name} onClick={() => {
                setCurCallModelLabel(item.value || item.name);
              }}>
                {item.value || item.name}
              </Menu.Item>
            );
          })}
      </Menu>
    );
  }, [labels, curCallModelLabel]);

  return (
    <Block name="timeline-controls" tag={Space} spread style={{ gridAutoColumns: 'auto' }}>
      {isFF(FF_DEV_2715) && mediaType === 'audio' ? renderControls() : (
        <Elem name="group" tag={Space} size="small" style={{ gridAutoColumns: 'auto' }}>
          {props.controls && Object.entries(props.controls).map(([name, enabled]) => {
            if (enabled === false) return;

            const Component = SideControls[name as keyof typeof SideControls];

            return isDefined(Component) && (
              <Component
                key={name}
                length={length}
                position={position - 1}
                volume={props.volume}
                onPositionChange={onPositionChange}
                onVolumeChange={props.onVolumeChange}
              />
            );
          })}
          {customControls?.left}
        </Elem>
      )}
      <Elem name="main-controls">
        <Elem name="group" tag={Space} collapsed>
          {extraControls}
        </Elem>
        <Elem name="group" tag={Space} collapsed>
          {customControls?.leftCenter}
          <AltControls
            showAlterantive={altControlsMode && !disableFrames}
            main={(
              <>
                {settings?.stepSize && !disableFrames && (
                  <ControlButton
                    onClick={stepHandlerWrapper(onStepBackward, settings.stepSize)}
                    hotkey={settings?.stepAltBack}
                    disabled={startReached}
                  >
                    {<IconPrev/>}
                  </ControlButton>
                )}
                <ControlButton
                  onClick={stepHandlerWrapper(onStepBackward)}
                  hotkey={settings?.stepBackHotkey}
                  disabled={startReached}
                >
                  <IconChevronLeft/>
                </ControlButton>
              </>
            )}
            alt={(
              <>
                <ControlButton
                  onClick={() => onRewind?.()}
                  disabled={startReached}
                  hotkey={settings?.skipToBeginning}
                >
                  <IconRewind/>
                </ControlButton>
                <ControlButton
                  onClick={() => onRewind?.(altHopSize)}
                  disabled={startReached}
                  hotkey={settings?.hopBackward}
                >
                  <IconBackward/>
                </ControlButton>
              </>
            )}
          />
          <ControlButton data-testid={`playback-button:${playing ? 'pause' : 'play'}`} onClick={handlePlay} hotkey={settings?.playpauseHotkey}>
            {playing ? <IconPause/> : <IconPlay/>}
          </ControlButton>
          <AltControls
            showAlterantive={altControlsMode && !disableFrames}
            main={(
              <>
                <ControlButton
                  onClick={stepHandlerWrapper(onStepForward)}
                  hotkey={settings?.stepForwardHotkey}
                  disabled={endReached}
                >
                  <IconChevronRight/>{}
                </ControlButton>
                {settings?.stepSize && !disableFrames && (
                  <ControlButton
                    disabled={endReached}
                    onClick={stepHandlerWrapper(onStepForward, settings.stepSize)}
                    hotkey={settings?.stepAltForward}
                  >
                    <IconNext/>
                  </ControlButton>
                )}
              </>
            )}
            alt={(
              <>
                <ControlButton
                  onClick={() => onForward?.(altHopSize)}
                  disabled={endReached}
                  hotkey={settings?.hopForward}
                >
                  <IconForward/>
                </ControlButton>
                <ControlButton
                  onClick={() => onForward?.()}
                  disabled={endReached}
                  hotkey={settings?.skipToEnd}
                >
                  <IconFastForward/>
                </ControlButton>
              </>
            )}
          />
          {customControls?.rightCenter}
        </Elem>
        <Elem name="group" tag={Space} collapsed>
          {!disableFrames && allowViewCollapse && (
            <ControlButton
              tooltip="Toggle Timeline"
              onClick={() => onToggleCollapsed?.(!collapsed)}
            >
              {collapsed ? <IconExpand/> : <IconCollapse/>}
            </ControlButton>
          )}
          {allowFullscreen && (
            <ControlButton
              tooltip="Fullscreen"
              onClick={() => onFullScreenToggle?.(false)}
            >
              {fullscreen ? (
                <IconFullscreenExit/>
              ) : (
                <IconFullscreen/>
              )}
            </ControlButton>
          )}
          <Elem name="group" tag={Space} collapsed>
            <Button
              tooltip={"call Segment Anything Model"}
              size={'small'}
              waiting={callModelLoading}
              onClick={callSamModelSingle}
            >sam</Button>
            <InputNumber
              size={'small'}
              addonAfter="帧"
              style={{width: "100px"}}
              value={samFrameLength}
              onChange={(v) => setSamFrameLength(v??0)}
            />
            <Button
              tooltip={"clean SAM cache"}
              size={'small'}
              waiting={callCleanSamCacheLoading}
              onClick={callCleanSamCache}
            >clean</Button>
          </Elem>
          {/*<Button*/}
          {/*  tooltip="Call Model"*/}
          {/*  type="text"*/}
          {/*  disabled={!curCallModelLabel}*/}
          {/*  waiting={callModelLoading}*/}
          {/*  style={{ width: 36, height: 36, padding: 0 }}*/}
          {/*  onClick={async () => {*/}
          {/*    setCallModelLoading(true);*/}
          {/*    await onCallModel?.(curCallModelLabel);*/}
          {/*    setCallModelLoading(false);*/}
          {/*  }}*/}
          {/*>*/}
          {/*  <IconRectangleTool />*/}
          {/*  <LsPlus />*/}
          {/*</Button>*/}
          {/*<Dropdown.Trigger*/}
          {/*  alignment="bottom-right"*/}
          {/*  content={dropdownContent}*/}
          {/*  style={{ width: 200 }}*/}
          {/*>*/}
          {/*  <Button*/}
          {/*    tooltip="Call Model Labels"*/}
          {/*    type="text"*/}
          {/*    style={{ width: '100%', height: 36, padding: 10 }}*/}
          {/*  >*/}
          {/*    {curCallModelLabel ?  <div>{curCallModelLabel}</div>  : <IconMenu />}*/}
          {/*  </Button>*/}
          {/*</Dropdown.Trigger>*/}
        </Elem>

      </Elem>

      <Elem name="group" tag={Space} size="small">
        {isFF(FF_DEV_2715) && mediaType === 'audio' ? (
          <>
            {customControls?.right}
            <TimeDurationControl
              startTime={0}
              endTime={duration}
              minTime={0}
              maxTime={duration}
              endTimeReadonly={true}
              currentTime={position}
              onChangeStartTime={onTimeUpdateChange}
            />
          </>
        ) : (
          <>
            {customControls?.right}
            <TimeDisplay
              currentTime={currentTime}
              duration={durationFormatted}
              length={length}
              position={position}
              framerate={frameRate}
              formatPosition={formatPosition}
            />
          </>
        )}
      </Elem>
    </Block>
  );
});

export const ControlButton: FC<ButtonProps & {disabled?: boolean}> = ({ children, ...props }) => {
  return (
    <Button
      {...props}
      type="text"
      style={{ width: 36, height: 36, padding: 0 }}
    >
      {children}
    </Button>
  );
};

interface TimeDisplay {
  currentTime: number;
  position: number;
  duration: number;
  framerate: number;
  length: number;
  formatPosition?: TimelineProps['formatPosition'];
}

const TimeDisplay: FC<TimeDisplay> = ({
  currentTime,
  position,
  duration,
  framerate,
  length,
  formatPosition,
}) => {
  const pos = position - 1;
  const formatter = formatPosition ?? positionFromTime;
  const commonOptions = { position: pos, fps: framerate, length };
  const currentTimeFormatted = formatter({ time: currentTime, ...commonOptions });
  const totalTimeFormatted = formatter({ time: duration, ...commonOptions });

  return (
    <Elem name="time">
      <Elem name="time-section">
        <Time time={currentTime} position={currentTimeFormatted}/>
      </Elem>
      <Elem name="time-section">
        <Time time={Math.max(duration, 0)} position={totalTimeFormatted}/>
      </Elem>
    </Elem>
  );
};

const Time: FC<{time: number, position: string}> = ({ time, position }) => {
  const timeDate = new Date(time * 1000).toISOString();
  const formatted = time > 3600
    ? timeDate.substr(11, 8)
    : timeDate.substr(14, 5);

  return (
    <>
      {formatted}{position ? <span>{position}</span> : null}
    </>
  );
};

type AltControlsProps = {
  showAlterantive: boolean,
  main: JSX.Element,
  alt: JSX.Element,
  hidden?: boolean,
}

const AltControls: FC<AltControlsProps> = (props) => {
  if (props.hidden) return null;
  return props.showAlterantive ? props.alt : props.main;
};

type ControlGroups = Record<TimelineCustomControls['position'], JSX.Element[]>;

const useCustomControls = (
  customControls?: TimelineCustomControls[],
): ControlGroups | null => {
  if (!customControls) return null;

  const groups = customControls?.reduce<ControlGroups>((groups, item) => {
    const group = groups[item.position] ?? [];
    const component = item.component instanceof Function ? item.component() : item.component;

    group.push(component);
    groups[item.position] = group;

    return groups;
  }, {} as ControlGroups);

  return groups;
};
