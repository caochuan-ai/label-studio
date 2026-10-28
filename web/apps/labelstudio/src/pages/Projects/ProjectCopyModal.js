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
  queued: '排队中', recovering: '恢复中', preparing: '准备项目', downloading: '下载中',
  cropping: '裁剪中', uploading: '上传中', saving: '保存标注', finished: '处理结束',
  failed: '失败', interrupted: '等待恢复',
};
const statusNames = { waiting: 'waiting', copying: 'copying', success: 'success', fail: 'fail' };
const css = element => cn('project-copy', { elem: element }).toClassName();
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
  const [storage, setStorage] = useState({ bucket: '', prefix: '', region_name: '', s3_endpoint: '',
    aws_access_key_id: '', aws_secret_access_key: '', aws_session_token: '', aws_sse_kms_key_id: '' });
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
      setHistoryLoading(false);
      if (result.error) setHistoryError(errorMessage(result));
      else {
        setHistoryError('');
        setJobs(result.jobs || []);
        const status = result.worker;

        setWorker(status ? { ...status, expiresAt: Date.now() + Math.max(0,
          (status.timeout - (status.server_time - status.last_heartbeat)) * 1000) } : null);
      }
      if (selectedId) {
        const detail = await api.projectCopyJob({ pk: project.id, job_id: selectedId }, { signal: controller.signal });

        if (disposed) return;
        if (detail.error) setHistoryError(errorMessage(detail));
        else setSelected(detail);
      }
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
    if (result.error) setError(errorMessage(result));
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
    if (result.error) setError(errorMessage(result));
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
    <Modal visible bare className={cn('project-copy-modal').toClassName()} onHide={onClose}
      width={820} style={{ maxWidth: 'calc(100vw - 32px)', minWidth: 0 }} closeOnClickOutside={false}>
      <div className={css()} role="dialog" aria-modal="true" aria-labelledby="project-copy-title">
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
        <div className={css('body')}>
          <form id="project-copy-form" onSubmit={submit} hidden={view !== 'config'}>
            <fieldset disabled={busy}>
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
                <div className={css('grid')}>
                  {storageField('bucket', 'Bucket', { required: true, placeholder: 'my-media-bucket' })}
                  {storageField('prefix', 'Prefix', { placeholder: '例如 cropped/（可选）' })}
                  {storageField('region_name', 'Region', { placeholder: '例如 ap-southeast-1（可选）' })}
                  {storageField('s3_endpoint', 'Endpoint', { placeholder: '默认 AWS S3 地址（可选）' })}
                </div>
                <details className={css('advanced')}>
                  <summary>访问凭证与高级选项<span>Access key / Session token / KMS</span></summary>
                  <div className={css('grid')}>
                    {storageField('aws_access_key_id', 'Access key ID')}
                    {storageField('aws_secret_access_key', 'Secret access key', { secret: true })}
                    {storageField('aws_session_token', 'Session token', { secret: true, placeholder: '可选' })}
                    {storageField('aws_sse_kms_key_id', 'KMS key ID', { placeholder: '可选' })}
                  </div>
                </details>
                <p className={css('hint')}>凭证留空时使用服务端 IAM 身份。裁剪后的文件将上传至该存储的独立子目录。</p>
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
              <ul className={css('history')}>
                {jobs.map(job => (
                  <li key={job.id}><button type="button" onClick={() => { setSelectedId(job.id); setSelected(job); }}
                    aria-pressed={job.id === selectedId}>
                    <strong>{job.new_project_name}</strong>
                    <span className={css('status')} data-status={job.status}>{statusNames[job.status] || job.status}</span>
                    <small>{new Date(job.created * 1000).toLocaleString()}</small>
                    <span className={css('count')}>{job.completed}/{job.total} 已完成</span>
                  </button></li>
                ))}
              </ul>
              {(offset > 0 || jobs.length === 50) && (
                <div className={css('pagination')}>
                  <Button size="compact" disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - 50))}>上一页</Button>
                  <Button size="compact" disabled={jobs.length < 50} onClick={() => setOffset(value => value + 50)}>下一页</Button>
                </div>
              )}
              {selected && (
                <section className={css('detail')} aria-live="polite">
                  <div className={css('detail-heading')}><h3>{selected.new_project_name}</h3>
                    <span className={css('status')} data-status={selected.status}>{statusNames[selected.status]}</span>
                  </div>
                  {selected.status === 'copying' && !selected.worker_ready && <p className={css('hint')}>负责此任务的 worker 已离线，等待重连后继续。</p>}
                  <p className={css('hint')}>裁剪区域：[{Object.entries(selected.crop).map(([key, value]) => `${key}: ${value}`).join(', ')}]</p>
                  <div className={css('progress-label')}><span>整体进度</span><strong>{Math.round(selected.progress)}%</strong></div>
                  <progress max="100" value={selected.progress} aria-label="项目复制进度" />
                  <p className={css('hint')}>已处理 {selected.completed + selected.failed}/{selected.total} · 成功 {selected.completed} · 失败 {selected.failed}</p>
                  <p>{phaseNames[selected.phase] || selected.phase}{selected.current_task ? ` · task ${selected.current_task}` : ''}</p>
                  {selected.status === 'copying' && <progress max="1" value={selected.file_progress} aria-label="当前阶段进度" />}
                  {selected.target_project && <a className={css('project-link')} href={absoluteURL(`/projects/${selected.target_project}/data`)}>打开新项目 →</a>}
                  {selected.error && <p className={css('error')}>{selected.error}</p>}
                  {!!selected.errors?.length && <ul className={css('error')}>{selected.errors.map(item => <li key={item.source}>task {item.source}: {item.error}</li>)}</ul>}
                  {selected.status === 'fail' && <Button onClick={retry} disabled={busy}>重试失败任务</Button>}
                </section>
              )}
            </section>
          )}
          {error && <p role="alert" className={css('error')}>{error}</p>}
        </div>
        <footer className={css('footer')}>
          <p><span className={css('queue-dot')} />单线程逐个处理，关闭窗口后继续运行</p>
          <div className={css('actions')}>
            <Button type="button" onClick={onClose}>{view === 'config' ? '取消' : '关闭'}</Button>
            {view === 'config' && <Button type="submit" form="project-copy-form" look="primary" disabled={busy}>{busy ? '正在提交…' : '开始复制'}</Button>}
          </div>
        </footer>
      </div>
    </Modal>
  );
};
