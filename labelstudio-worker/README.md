# Label Studio Copy Worker

独立项目裁剪复制服务，自带 FFmpeg、ffprobe、Pillow 和 S3 SDK。worker 主动连接 Label Studio；默认 8079 端口仅提供健康检查，不需要 Label Studio 或浏览器反向访问 worker。

## 部署

1. 更新 Label Studio 并执行数据库迁移：

   ```sh
   python3 label_studio/manage.py migrate
   ```

   `projects.0027_project_copy` 保存目标项目和 task 映射；`projects.0028_copy_worker_queue` 保存 app 端队列、历史和 worker 心跳。**Label Studio app 无需任何新的环境变量。**

2. 在本目录创建 `.env`，只需配置：

   ```dotenv
   LABEL_STUDIO_URL=http://labelstudio-host:8080
   LABEL_STUDIO_TOKEN=your-label-studio-user-api-token
   ```

   Token 使用 Label Studio 的用户 API Token，按现有 `Authorization: Token ...` 机制验证。worker 仅领取 **该 Token 用户创建、且当前仍有权限访问源项目** 的复制任务；请使用提交复制配置的用户的 Token。不会把用户 Token 从浏览器或 app 转发给 worker。

3. 启动：

   ```sh
   docker compose -f compose.yml up -d --build
   ```

   独立构建：`docker build -t labelstudio-worker:local .`。在仓库根目录构建时使用 `docker build -t labelstudio-worker:local labelstudio-worker`。

4. 在项目卡片菜单选择 Copy，填写新项目名、画面截取和 S3 配置。无需 worker 地址。worker 启动后立即发送一次心跳，然后每 **10 秒**发送心跳、领取任务并上报进度。

`LABEL_STUDIO_URL` 必须能从 worker 容器访问。容器中的 localhost 表示该容器；访问宿主机可使用对应 Docker 主机地址。`compose.yml` 默认限制 1 CPU、2 GiB 内存，挂载命名卷 `/data` 保存固定 worker ID 和恢复清单。请保留数据卷；更换 Token 所属用户时使用新的数据卷，避免沿用其他用户的 worker ID。目录权限 0700、SQLite 权限 0600。Token 只通过环境变量读取，任务数据库不保存 Token；数据库仍包含处理所需 S3 凭据，需保护数据卷和备份。跨主机通信建议使用 HTTPS。

## 心跳、状态与恢复

复制弹窗默认读取源项目最早创建的 Source Storage，包含 AK/SK、Session token、Region、Endpoint、Prefix 和 KMS 配置。第一个存储不是 S3 或没有存储时，需要手动填写目标 S3。只有具备项目配置权限的用户可读取默认凭证；响应禁止缓存，历史记录不返回密钥。

**必须修改至少一项目标存储配置后才能开始复制**（例如修改 Prefix）。前端和后端都会校验；仅改项目名或裁剪区域、仅增加空格/首尾斜线不算修改。目标 AK/SK 必填，临时凭证还需要 Session token。worker 直接使用任务中的凭证，无需配置 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`。新建的 Source Storage 也使用这组凭证。

复制历史按创建时间倒序展示项目内有权限查看的记录，显示操作人、状态和进度。点击每行最后的“详情”查看进度、报错和新项目入口；仅提交者可以重试自己的失败任务。

- 首次经过 API Token 验证的心跳自动注册 worker，无需手工配置 app。
- 最近心跳距今不超过 30 秒时为 `Ready`，超过 30 秒为 `not Ready`。忙碌中的 worker 继续心跳，仍为 Ready。
- app 默认使用 4 个 uWSGI 进程，因此注册/心跳使用 app 现有数据库共享，避免进程内存造成状态随机变化。不需要 Redis、额外端口或环境变量。
- 没有 Ready worker 时仍可提交任务，状态为 `waiting`，待 worker 连接后领取。
- 每个 worker 同时只领取一个项目，逐个处理媒体。心跳响应丢失时会重新返回相同分配；完成报告可重复上报，幂等创建目标项目和任务。
- worker 离线后保留正在执行的任务归属，历史显示 `copying` 和离线提示，原 worker 携带原数据卷重连后继续。不会因暂时断网将同一项目并发交给另一台 worker。离线并不表示任务已成功或永久失败。
- 任务状态为 `waiting` / `copying` / `success` / `fail`。任意文件失败时最终状态为 fail，保留成功项并支持重试。重试递增 attempt，拒绝旧执行批次的进度和提交。
- app 保存任务和历史，worker 离线或重启不会丢失历史。worker 数据卷丢失会丢失其固定身份；运行中的任务应恢复原卷，不会自动转移给陌生 worker。

## API

所有复制管理接口都在 **Label Studio** 上，浏览器使用登录会话，worker 使用标准用户 Token。

| 接口 | 用途 |
| --- | --- |
| `POST /api/projects/copy/heartbeat/` | Token 鉴权、注册、心跳、上报进度并领取一个任务 |
| `GET /api/projects/{project_id}/copy/defaults/` | 源项目第一个存储的默认配置（含凭证，需项目配置权限） |
| `POST /api/projects/{project_id}/copy/jobs/` | 创建复制任务，返回 202 |
| `GET /api/projects/{project_id}/copy/jobs/?offset=0` | 项目历史（时间倒序，50 条/页，含操作人）及当前用户的 worker 状态 |
| `GET /api/projects/{project_id}/copy/jobs/{job_id}/` | 单个任务及文件阶段、失败详情 |
| `POST /api/projects/{project_id}/copy/jobs/{job_id}/` | 重试 fail 任务 |
| worker `GET /health` | 执行线程、心跳线程存活状态及最近连接是否 Ready |

心跳请求：

```http
POST /api/projects/copy/heartbeat/
Authorization: Token <LABEL_STUDIO_TOKEN>
Content-Type: application/json
```

```json
{"worker_id": "dd7aac90-c3be-4fd2-8fe0-fd112bd90c29", "report": null}
```

返回 `{ "job": null, "interval": 10, "timeout": 30 }` 或包含 id、owner、attempt 和 request 的 job。执行期间 report 包含 id、attempt、status、phase、total、completed、failed、current_task、file_progress、error 和 errors。领取任务后，worker 回调复制接口携带 `X-Copy-Worker` 和 `X-Copy-Attempt`，用于校验归属及拒绝过期重试。

创建复制任务示例：

```json
{
  "new_project_name": "Original - cropped",
  "idempotency_key": "dd7aac90-c3be-4fd2-8fe0-fd112bd90c29",
  "crop": {"x0": 100, "y0": 100, "x1": 1380, "y1": 820},
  "source_storage": {
    "bucket": "destination-bucket",
    "prefix": "cropped-projects",
    "region_name": "cn-northwest-1",
    "aws_access_key_id": "<target-access-key>",
    "aws_secret_access_key": "<target-secret-key>"
  }
}
```

相同 UUID 和相同配置可以安全重试提交。进度表示已处理项（包括失败项）占比，成功与否由 status 和 failed 数量判断。历史响应不包含 S3 密钥。

## 处理与恢复

- 全局一个执行线程，按项目和 task 顺序处理。FFmpeg 解码/编码/滤镜限制单线程，S3 传输关闭线程并发。独立心跳线程每 10 秒拉取任务并上报进度，长视频编码不会阻塞心跳。
- 一个 task 完成下载、裁剪、上传和数据库提交后，清理临时文件，再处理下一个。不会把整个项目的媒体放入内存或一次性下载到本地。
- 新项目复用原标注配置和项目设置，S3 Source Storage 使用 `prefix/copy-<job-id>/`。空目标 prefix 合法；文件名采用原 task ID，重试覆盖同一目标对象。
- 图片输出 PNG；视频输出 H.264 MP4 / yuv420p，有音频时保留并转为 AAC。视频重新编码，默认 CRF 18；不做时间截取、缩放或主动改帧率。编码后校验尺寸、帧数和时长。
- annotations、predictions、annotation drafts 同步变换，保留标签、得分、模型版本、作者等原始属性。同一个 task 内的父标注、父 prediction、draft 关系重新关联；跨 task 的父关系和 prediction neighbors 不指向旧项目。ML backend、webhook、旧云存储连接及任务锁不复制。
- 新 task、标注、prediction、draft 和 Storage Link 在 Label Studio 的一个事务中提交。响应丢失时按复制映射找回结果，防止重复创建。Storage Link 防止后续 Source Storage Sync 重复导入。
- 运行中的任务在 worker 重启后先向 app 确认原有分配，再恢复处理；启动时取得文件锁，只允许一个执行进程共享该数据目录。不要使用 `uvicorn --workers 2` 或扩容同一数据卷。异常退出后重新处理未完成的当前文件，已提交 task 不重做。
- 同一个文件连续中断执行进程三次后标记为失败并处理下一个，避免坏文件或 OOM 引起无限重启；调整资源配置后可手动重试。
- 单文件失败记为失败项，继续处理后续文件；整个作业结束为 `fail`（包括部分文件失败）。历史中支持重试失败项。上传成功、提交失败时对象会保留供重试；未使用的目标对象可在确认不重试后手动清理。

## 支持范围与约束

- 每个项目的配置包含一个顶层 `$field` 的 Image 或 Video；每个 task 对应一个媒体文件。多媒体字段、图像列表、动画/多页图片会明确报错。
- 原媒体支持 HTTP(S)、Label Studio 本地上传和项目已配置的 S3。S3 使用源项目凭据签名下载，不要求新 Storage 能读旧 Bucket。
- 裁剪使用显示方向下原始画面的像素坐标，区域为 `[x0, x1) × [y0, y1)`。每个文件单独校验范围，越界报错，不自动缩放。视频输出宽高必须为偶数；支持奇数起点并启用精确裁剪。
- 仅处理无旋转的 `rectangle`、`rectanglelabels`、`videorectangle` 空间标注；保留附属 labels/choices 等非空间数据。旋转框、polygon、mask 等明确报错。框与裁剪区域求交，移除完全不可见的框和悬空关系，并更新百分比坐标和图像尺寸。
- 视频轨迹在裁剪边界交叉处补充关键帧，保证逐帧插值等于裁剪后的原轨迹，避免只裁剪两端关键帧造成中间帧偏移。不会把长视频轨迹全部展开成逐帧 JSON。
- 作业初始化时记录原项目的最大 task ID，之后新增的 task 不进入本次复制。每个 task 读取当时的标注数据，并在提交前检查版本；处理期间发生修改则该项失败，可重试。长任务运行期间尽量避免更改源项目标注配置。
- 目标 S3 需要 List/Get/Put 权限；使用 KMS 时还需要对应密钥权限。目标凭证随任务传递给 worker，并保存到新项目的 Source Storage。浏览器播放仍需配置目标 Bucket 的 CORS。

## 执行日志

升级 worker 代码后，重新构建并创建容器（单纯 restart 不会更新镜像）：

```sh
cd labelstudio-worker
docker compose -f compose.yml up -d --build labelstudio-worker
docker compose -f compose.yml logs -f --tail=100 labelstudio-worker
# 或使用现有容器名：
sudo docker logs --tail=100 -f labelstudio-worker-labelstudio-worker-1
```

INFO 日志输出到标准输出，包含时间、worker/job/task ID、attempt、阶段和耗时：

```text
event=job_claimed job=<uuid> project=12 attempt=1 worker=<uuid>
event=job_start job=<uuid> project=12 attempt=1
event=storage_check job=<uuid>
event=stage_start job=<uuid> task=123 phase=downloading
event=stage_finished job=<uuid> task=123 phase=downloading elapsed=2.30s
event=stage_start job=<uuid> task=123 phase=cropping
event=stage_progress job=<uuid> task=123 phase=cropping progress=42% elapsed=10.20s
event=stage_start job=<uuid> task=123 phase=transforming
event=stage_start job=<uuid> task=123 phase=uploading
event=stage_start job=<uuid> task=123 phase=saving
event=task_finished job=<uuid> task=123 target_task=456 output_bytes=123456 elapsed=34.50s
event=job_finished job=<uuid> status=success completed=1 failed=0 elapsed=36.00s
```

长步骤的进度日志最多每 10 秒输出一次，完成时补充 100%（下载/上传可用时）。成功心跳首次、恢复连接时及每 60 秒记录一次；实际心跳仍每 10 秒发送。连接失败输出 `heartbeat_failed`。文件失败输出 `task_failed`，整体初始化失败输出 `job_failed`，包含阶段、脱敏错误及代码位置；S3 错误包含服务错误码和 HTTP 状态。不会打印 AK/SK、Token、请求体或签名媒体 URL。

`fail` 不会自动重新执行；需手动点击重试。心跳重传完成状态、页面轮询历史不等于重试。S3 SDK 在单次操作内仍有有限次数的网络重试。

## 资源参数

### NoCredentialsError

`LABEL_STUDIO_TOKEN` 只验证 Label Studio API 用户身份，不提供 AWS/S3 权限。如果复制任务出现 `NoCredentialsError`，说明 worker 没有取得目标 S3 凭证。可以：

- 在复制弹窗的“新 Source Storage → 访问凭证与高级选项”中填写 Access key ID、Secret access key（临时凭证还需 Session token），然后重新提交复制。修改表单不会修改已经创建的历史任务。
- 旧记录中缺少 AK/SK 的任务不能直接重试，请补齐配置后创建新任务。已经包含有效凭证的任务可以在排除故障后手动重试。

这属于任务执行失败，应显示在 `fail` 任务详情中，不影响历史列表读取。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `WORKER_DATA_DIR` | `/data` | SQLite、锁和临时文件目录 |
| `MAX_MEDIA_BYTES` | `21474836480` | 单个输入或输出文件最大 20 GiB |
| `MEDIA_TIMEOUT_SECONDS` | `21600` | 单文件媒体操作超时，6 小时 |
| `MIN_FREE_BYTES` | `1073741824` | 临时磁盘至少保留 1 GiB |
| `MAX_FRAME_PIXELS` | `16777216` | 解码前限制图片/视频单帧像素数，默认约 16.8 MP |

## 验证

```sh
# 独立 worker：Python 3.9+，需要 ffmpeg 和 ffprobe
python -m pip install -r requirements.txt pytest httpx
PYTHONPATH=. pytest -q tests

# Label Studio bridge：使用主应用依赖和独立测试数据库
PYTHONPATH=.:label_studio DJANGO_DB=sqlite BASE_DATA_DIR=/tmp/labelstudio-copy-test \
  python label_studio/manage.py test projects.tests.test_copy_api
```

测试覆盖裁剪边界、每帧轨迹插值、原数据不变、鉴权、幂等、失败重试、重启恢复、实际 PNG/H.264 裁剪和 Label Studio 事务关联。测试不会连接真实 S3 或修改生产项目。
