import React, { useEffect, useRef, useState } from 'react';
import { Button } from '../../components';
import { Modal } from '../../components/Modal/Modal';
import { useAPI } from '../../providers/ApiProvider';
import { absoluteURL } from '../../utils/helpers';
import { cn } from '../../utils/bem';
import { LsCross } from '../../assets/icons';
import './ProjectCopyModal.styl';

const newKey = () => '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, c =>
  (Number(c) ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (Number(c) / 4)))).toString(16));
const phaseNames = {
  loading_task: '读取任务', queued: '排队中', recovering: '恢复中', preparing: '准备项目', downloading: '下载中',
  cropping: '裁剪中', transforming: '转换标注', uploading: '上传中', saving: '保存标注', finished: '处理结束',
  failed: '失败', interrupted: '等待恢复',
};
const statusNames = { waiting: 'waiting', copying: 'copying', success: 'success', fail: 'fail' };
const css = element => cn('project-copy', { elem: element }).toClassName();
// A successful job response can contain its own `error`; only API failures lack a job ID.
const isApiError = result => Boolean(result?.error && !result?.id);
const jobErrorMessage = message => {
  if (message?.startsWith('NoCredentialsError:')) {
    return 'worker 未找到 S3 凭证。请在“新 Source Storage → 访问凭证与高级选项”填写 Access key ID 和 Secret access key 后重新提交复制。Label Studio Token 仅用于访问 Label Studio，不能替代 S3 凭证。';
  }
  if (message?.startsWith('PartialCredentialsError:')) {
    return 'S3 凭证不完整。Access key ID 和 Secret access key 必须成对配置；使用临时凭证时还需填写 Session token。';
  }
  return message;
};
const errorMessage = response => {
  const detail = response?.response?.validation_errors ?? response?.response?.detail ?? response?.error;
  const messages = value => {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value.map(messages).join('；');
    if (value && typeof value === 'object') return Object.entries(value).map(([key, message]) =>
      `${key === 'non_field_errors' ? '' : `${key}: `}${messages(message)}`).join('；');
    return '请求失败，请稍后重试。';
  };
  const message = messages(detail);

  return message;
};

const emptyStorage = { bucket: '', prefix: '', region_name: '', s3_endpoint: '',
  aws_access_key_id: '', aws_secret_access_key: '', aws_session_token: '', aws_sse_kms_key_id: '' };
const normalizeStorage = storage => JSON.stringify(Object.keys(emptyStorage).map(key => {
  const value = (storage[key] || '').trim();

  return key === 'prefix' ? value.replace(/^\/+|\/+$/g, '') : key === 's3_endpoint' ? value.replace(/\/+$/, '') : value;
}));
const formatTime = timestamp => timestamp ? new Date(timestamp * 1000).toLocaleString() : '—';

const CopyIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
    <rect x="8" y="8" width="12" height="13" rx="2" />
    <path d="M15 5V4a1 1 0 0 0-1-1H5a2 2 0 0 0-2 2v10a1 1 0 0 0 1 1h1" strokeLinecap="round" />
  </svg>
);

const SectionHeading = ({ number, title, children }) => (
  <div className={css('section-heading')}>
    <span className={css('section-number')}>{number}</span>
    <h3>{title}</h3>
    {children}
  </div>
);

export const ProjectCopyModal = ({ project, onClose }) => {
  const { api } = useAPI();
  const [worker, setWorker] = useState(null);
  const [now, setNow] = useState(Date.now);
  const [name, setName] = useState(`${project.title} Copy`);
  const [crop, setCrop] = useState({ x0: '0', y0: '0', x1: '', y1: '' });
  const [storage, setStorage] = useState(emptyStorage);
  const [defaults, setDefaults] = useState(null);
  const [defaultsError, setDefaultsError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [jobs, setJobs] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [error, setError] = useState('');
  const [historyError, setHistoryError] = useState('');
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState('config');
  const [historyLoading, setHistoryLoading] = useState(true);
  const idempotencyKey = useRef(newKey());
  const mounted = useRef(true);
  const detailRef = useRef(null);
  const bodyRef = useRef(null);
  const returnFocus = useRef(null);
  const storageChanged = defaults && normalizeStorage(storage) !== normalizeStorage(defaults.source_storage);
  const closeDetail = () => { setSelectedId(null); setSelected(null); setDetailError(''); setError(''); };

  useEffect(() => {
    let disposed = false;
    const controller = new AbortController();

    api.projectCopyDefaults({ pk: project.id }, { signal: controller.signal }).then(result => {
      if (disposed) return;
      if (isApiError(result)) setDefaultsError(errorMessage(result));
      else {
        const values = { ...emptyStorage, ...result.source_storage };

        setDefaults({ ...result, source_storage: values });
        setStorage(values);
      }
    }).catch(() => { if (!disposed) setDefaultsError('无法读取 Source Storage，请关闭后重试。'); });
    return () => { disposed = true; controller.abort(); };
  }, [api, project.id]);

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, [view, offset]);

  useEffect(() => {
    if (!selectedId) return;
    returnFocus.current = document.activeElement;
    detailRef.current?.querySelector('button')?.focus();
    return () => returnFocus.current?.focus();
  }, [selectedId]);

  useEffect(() => {
    mounted.current = true;
    const timer = setInterval(() => setNow(Date.now()), 1000);

    return () => { mounted.current = false; clearInterval(timer); };
  }, []);

  useEffect(() => {
    let disposed = false;
    let timer;
    const controller = new AbortController();
    const poll = async () => {
      const result = await api.projectCopyJobs({ pk: project.id, offset }, { signal: controller.signal });

      if (disposed) return;
      const pollError = isApiError(result) ? errorMessage(result) : '';

      if (!pollError) {
        setJobs([...(result.jobs || [])].sort((a, b) => b.created - a.created || b.id.localeCompare(a.id)));
        const status = result.worker;

        setWorker(status ? { ...status, expiresAt: Date.now() + Math.max(0,
          (status.timeout - (status.server_time - status.last_heartbeat)) * 1000) } : null);
      }
      if (selectedId) {
        const detail = await api.projectCopyJob({ pk: project.id, job_id: selectedId }, { signal: controller.signal });

        if (disposed) return;
        if (isApiError(detail)) setDetailError(errorMessage(detail));
        else { setSelected(detail); setDetailError(''); }
      }
      // Keep the previous notice until the whole poll finishes, avoiding a remove/reinsert layout jump.
      setHistoryError(pollError);
      setHistoryLoading(false);
      timer = setTimeout(poll, 3000);
    };

    poll();
    return () => { disposed = true; clearTimeout(timer); controller.abort(); };
  }, [api, project.id, selectedId, offset, refresh]);

  const changed = setter => value => { setter(value); idempotencyKey.current = newKey(); };
  const refreshHistory = () => {
    setHistoryLoading(true);
    setHistoryError('');
    setRefresh(value => value + 1);
  };
  const submit = async event => {
    event.preventDefault();
    if (busy) return;
    if (!defaults || !storageChanged) {
      setError('请至少修改一项新 Source Storage 配置后再开始复制。');
      return;
    }
    if (!storage.aws_access_key_id.trim() || !storage.aws_secret_access_key.trim()) {
      setError('请补齐新 Source Storage 的 Access key ID 和 Secret access key。');
      return;
    }
    const coordinates = Object.fromEntries(Object.entries(crop).map(([key, value]) => [key, Number(value)]));

    if (Object.values(crop).some(value => value === '') || Object.values(coordinates).some(value => !Number.isInteger(value) || value < 0) ||
      coordinates.x1 <= coordinates.x0 || coordinates.y1 <= coordinates.y0) {
      setError('请输入有效的像素坐标：x1 > x0，y1 > y0。');
      return;
    }
    setBusy(true);
    setError('');
    const result = await api.createProjectCopy({ pk: project.id }, { body: {
      new_project_name: name.trim(), crop: coordinates,
      source_storage: storage, idempotency_key: idempotencyKey.current,
    } });

    if (!mounted.current) return;
    setBusy(false);
    if (isApiError(result)) setError(errorMessage(result));
    else {
      setSelectedId(result.id);
      setSelected(result);
      setView('history');
      setOffset(0);
      setRefresh(value => value + 1);
      // Keep the request key until configuration changes, so a second click cannot duplicate a job.
    }
  };
  const retry = async () => {
    setBusy(true);
    const result = await api.retryProjectCopy({ pk: project.id, job_id: selectedId }, { body: {} });

    if (!mounted.current) return;
    setBusy(false);
    if (isApiError(result)) setError(errorMessage(result));
    else { setSelected(result); setRefresh(value => value + 1); }
  };

  const workerReady = !!worker?.ready && now <= worker.expiresAt;
  const workerLabel = workerReady ? 'Ready' : 'not Ready';
  const cropWidth = Number(crop.x1) - Number(crop.x0);
  const cropHeight = Number(crop.y1) - Number(crop.y0);
  const validSize = crop.x1 !== '' && crop.y1 !== '' && cropWidth > 0 && cropHeight > 0;
  const storageField = (key, label, { required, placeholder, secret } = {}) => (
    <label className={css('field')} key={key}>
      <span>{label}{required && <span className={css('required')} aria-hidden="true"> *</span>}</span>
      <input aria-label={label} required={required} autoComplete="off" value={storage[key]}
        placeholder={placeholder} type={secret ? 'password' : 'text'}
        onChange={e => changed(setStorage)({ ...storage, [key]: e.target.value })} />
    </label>
  );

  return (
    <>
      <Modal visible bare allowClose={!selectedId} className={cn('project-copy-modal').toClassName()} onHide={onClose}
        width={view === 'history' ? 1000 : 820} style={{ maxWidth: 'calc(100vw - 32px)', minWidth: 0 }} closeOnClickOutside={false}>
        <div className={css()} role="dialog" aria-modal={!selectedId} aria-hidden={selectedId ? true : undefined} aria-labelledby="project-copy-title">
          <header className={css('header')}>
            <div className={css('icon')}><CopyIcon /></div>
            <div className={css('title')}>
              <h2 id="project-copy-title">复制项目</h2>
              <p title={project.title}>源项目 <span>{project.title}</span></p>
            </div>
            <button type="button" className={css('close')} aria-label="关闭复制窗口" onClick={onClose}><LsCross /></button>
          </header>
          <nav className={css('tabs')} aria-label="复制项目视图">
            <button type="button" aria-pressed={view === 'config'} onClick={() => setView('config')}>复制配置</button>
            <button type="button" aria-pressed={view === 'history'} onClick={() => setView('history')}>
            复制历史{jobs.length > 0 && <span>{jobs.length}</span>}
            </button>
          </nav>
          <div ref={bodyRef} className={css('body')}>
            <form id="project-copy-form" onSubmit={submit} hidden={view !== 'config'}>
              <fieldset disabled={busy || !defaults}>
                <section className={css('section')}>
                  <SectionHeading number="01" title="基本信息" />
                  <div className={css('grid')}>
                    <label className={css('field')}>
                      <span>新项目名称 <span className={css('required')} aria-hidden="true">*</span></span>
                      <input aria-label="新项目名称" required maxLength={200} value={name}
                        onChange={e => changed(setName)(e.target.value)} />
                    </label>
                    <div className={css('worker')}>
                      <span>Copy worker</span>
                      <div role="status" aria-label="Worker 状态" className={css('worker-state')} data-ready={workerReady}>
                        <span className={css('worker-dot')} />{workerLabel}
                      </div>
                      <small>{workerReady ? '每 10 秒更新心跳，30 秒无响应则离线。' : 'worker 未就绪，提交后将排队等待。'}</small>
                    </div>
                  </div>
                </section>
                <section className={css('section')}>
                  <SectionHeading number="02" title="画面截取"><span className={css('tag')}>像素坐标</span></SectionHeading>
                  <div className={css('crop-panel')}>
                    <div className={css('coordinates')}>
                      {Object.entries(crop).map(([key, value]) => (
                        <label className={css('field')} key={key}>
                          <span>{key.endsWith('0') ? '起点' : '终点'} <b>{key}</b></span>
                          <input aria-label={key} required type="number" min="0" step="1" value={value} placeholder={key === 'x1' ? '如 1920' : '如 1080'}
                            onChange={e => changed(setCrop)({ ...crop, [key]: e.target.value })} />
                        </label>
                      ))}
                    </div>
                    <div className={css('crop-summary')}>
                      <span>输出尺寸</span>
                      <strong>{validSize ? `${cropWidth} × ${cropHeight} px` : '填写终点坐标后计算'}</strong>
                    </div>
                  </div>
                  <p className={css('hint')}>终点不包含在截取范围内，视频宽高须为偶数。支持无旋转矩形框，自动调整标注和预测坐标。</p>
                </section>
                <section className={css('section')}>
                  <SectionHeading number="03" title="新 Source Storage"><span className={css('tag')}>S3</span></SectionHeading>
                  <p className={css('storage-hint')} data-changed={!!storageChanged}>
                    {defaultsError || (!defaults ? '正在读取源项目的 Source Storage…' : defaults.message ||
                    `已带入第一个 Source Storage：${defaults.storage_title}`)}
                    {defaults && <span>{storageChanged ? '已修改目标配置，可以开始复制。' : '请至少修改一项存储配置（如 Prefix）后再开始复制。'}</span>}
                  </p>
                  <div className={css('grid')}>
                    {storageField('bucket', 'Bucket', { required: true, placeholder: 'my-media-bucket' })}
                    {storageField('prefix', 'Prefix', { placeholder: '例如 cropped/（可选）' })}
                    {storageField('region_name', 'Region', { placeholder: '例如 ap-southeast-1（可选）' })}
                    {storageField('s3_endpoint', 'Endpoint', { placeholder: '默认 AWS S3 地址（可选）' })}
                  </div>
                  <details className={css('advanced')} open={defaults && (!storage.aws_access_key_id || !storage.aws_secret_access_key) ? true : undefined}>
                    <summary>访问凭证与高级选项<span>Access key / Session token / KMS</span></summary>
                    <div className={css('grid')}>
                      {storageField('aws_access_key_id', 'Access key ID', { required: true })}
                      {storageField('aws_secret_access_key', 'Secret access key', { secret: true, required: true })}
                      {storageField('aws_session_token', 'Session token', { secret: true, placeholder: '可选' })}
                      {storageField('aws_sse_kms_key_id', 'KMS key ID', { placeholder: '可选' })}
                    </div>
                  </details>
                  <p className={css('hint')}>AK/SK 随复制任务提供给 worker，无需在 worker 容器配置 S3 密钥。源存储未配置密钥时，请在此补齐；临时凭证还需 Session token。</p>
                </section>
              </fieldset>
            </form>
            {view === 'history' && (
              <section className={css('history-panel')} aria-label="复制历史">
                <div className={css('history-heading')}>
                  <div><h3>复制记录</h3><p className={css('hint')}>关闭窗口后任务继续运行，可在这里查看进度。</p></div>
                  <Button type="button" size="compact" onClick={refreshHistory}>刷新历史</Button>
                </div>
                <div className={css('source')}><span>Copy worker</span><strong className={css('worker-state')} data-ready={workerReady}>{workerLabel}</strong><span>每 10 秒心跳 · 30 秒超时</span></div>
                {historyError ? (
                  <div role="alert" className={css('notice')}><strong>暂时无法读取复制记录</strong><p>{historyError}</p></div>
                ) : !jobs.length && (
                  <div className={css('empty')}>
                    <div className={css('empty-icon')}><CopyIcon /></div>
                    <h3>{historyLoading ? '正在读取复制记录…' : '还没有复制记录'}</h3>
                    <p>提交复制配置后，处理进度会显示在这里。</p>
                  </div>
                )}
                {!!jobs.length && (
                  <div className={css('table-wrap')}>
                    <table className={css('history-table')} aria-label="复制历史列表">
                      <thead><tr><th>新项目名称</th><th>操作人 / 创建时间</th><th>状态</th><th>进度</th><th>操作</th></tr></thead>
                      <tbody>{jobs.map(job => (
                        <tr key={job.id}>
                          <td><strong title={job.new_project_name}>{job.new_project_name}</strong></td>
                          <td><span>{job.operator?.name || '—'}</span><small>{formatTime(job.created)}</small></td>
                          <td><span className={css('status')} data-status={job.status}>{statusNames[job.status] || job.status}</span></td>
                          <td><span>{Math.round(job.progress || 0)}%</span><small>{job.completed}/{job.total} 成功</small></td>
                          <td><button type="button" className={css('detail-button')} aria-label={`详情：${job.new_project_name}`}
                            onClick={() => { setDetailError(''); setError(''); setSelectedId(job.id); setSelected(job); }}>详情</button></td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                )}
                {(offset > 0 || jobs.length === 50) && (
                  <div className={css('pagination')}>
                    <Button size="compact" disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - 50))}>上一页</Button>
                    <Button size="compact" disabled={jobs.length < 50} onClick={() => setOffset(value => value + 50)}>下一页</Button>
                  </div>
                )}

              </section>
            )}
            {error && !selectedId && <p role="alert" className={css('error')}>{error}</p>}
          </div>
          <footer className={css('footer')}>
            <p><span className={css('queue-dot')} />单线程逐个处理，关闭窗口后继续运行</p>
            <div className={css('actions')}>
              <Button type="button" onClick={onClose}>{view === 'config' ? '取消' : '关闭'}</Button>
              {view === 'config' && <Button type="submit" form="project-copy-form" look="primary" disabled={busy || !storageChanged}>{busy ? '正在提交…' : '开始复制'}</Button>}
            </div>
          </footer>
        </div>
      </Modal>
      {selected && (
        <Modal visible bare className={cn('project-copy-modal').toClassName()} onHide={closeDetail}
          width={720} style={{ maxWidth: 'calc(100vw - 32px)', minWidth: 0 }} closeOnClickOutside={false}>
          <div ref={detailRef} className={css()} role="dialog" aria-modal="true" aria-labelledby="copy-detail-title"
            onKeyDown={event => {
              if (event.key !== 'Tab') return;
              const focusable = [...detailRef.current.querySelectorAll('button:not(:disabled), a[href]')];
              const first = focusable[0], last = focusable[focusable.length - 1];

              if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
              else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
            }}>
            <header className={css('header')}>
              <div className={css('icon')}><CopyIcon /></div>
              <div className={css('title')}><h2 id="copy-detail-title">复制详情</h2><p>处理进度与执行结果</p></div>
              <button type="button" className={css('close')} aria-label="关闭复制详情" onClick={closeDetail}><LsCross /></button>
            </header>
            <div className={css('body')}>
              {detailError && <div role="alert" className={css('notice')}>暂时无法更新详情：{detailError}</div>}
              <section className={css('detail')}>
                <div className={css('detail-heading')}><h3>{selected.new_project_name}</h3>
                  <span className={css('status')} data-status={selected.status}>{statusNames[selected.status]}</span>
                </div>
                <dl className={css('metadata')}>
                  <div><dt>操作人</dt><dd>{selected.operator?.name || '—'}</dd></div>
                  <div><dt>创建时间</dt><dd>{formatTime(selected.created)}</dd></div>
                  <div><dt>任务 ID</dt><dd>{selected.id}</dd></div>
                  <div><dt>目标存储</dt><dd>{selected.source_storage?.bucket || '—'} / {selected.source_storage?.prefix || ''}</dd></div>
                </dl>
                {selected.status === 'copying' && !selected.worker_ready && <p className={css('hint')}>负责此任务的 worker 已离线，等待重连后继续。</p>}
                <p className={css('hint')}>裁剪区域：[{Object.entries(selected.crop || {}).map(([key, value]) => `${key}: ${value}`).join(', ')}]</p>
                <div className={css('progress-label')}><span>整体进度</span><strong>{Math.round(selected.progress)}%</strong></div>
                <progress max="100" value={selected.progress} aria-label="项目复制进度" />
                <p className={css('hint')}>已处理 {selected.completed + selected.failed}/{selected.total} · 成功 {selected.completed} · 失败 {selected.failed}</p>
                <p>{phaseNames[selected.phase] || selected.phase}{selected.current_task ? ` · task ${selected.current_task}` : ''}</p>
                {selected.status === 'copying' && <progress max="1" value={selected.file_progress} aria-label="当前阶段进度" />}
                {selected.target_project && <a className={css('project-link')} href={absoluteURL(`/projects/${selected.target_project}/data`)}>打开新项目 →</a>}
                {selected.error && <p className={css('error')}>{jobErrorMessage(selected.error)}</p>}
                {!!selected.errors?.length && <ul className={css('error')}>{selected.errors.map(item => <li key={item.source}>task {item.source}: {jobErrorMessage(item.error)}</li>)}</ul>}
                {selected.status === 'fail' && selected.can_retry !== false && <Button onClick={retry} disabled={busy}>重试失败任务</Button>}
              </section>

              {error && <p role="alert" className={css('error')}>{error}</p>}
            </div>
            <footer className={css('footer')}><p>关闭详情后任务继续运行</p><Button onClick={closeDetail}>返回历史</Button></footer>
          </div>
        </Modal>
      )}
    </>
  );
};
