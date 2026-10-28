import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProjectCopyModal } from './ProjectCopyModal';

const mockApi = {
  projectCopyDefaults: jest.fn(), projectCopyJobs: jest.fn(), projectCopyJob: jest.fn(), createProjectCopy: jest.fn(), retryProjectCopy: jest.fn(),
};

jest.mock('../../providers/ApiProvider', () => ({ useAPI: () => ({ api: mockApi }) }));
jest.mock('../../components', () => ({ Button: ({ children, look, size, ...props }) => <button {...props}>{children}</button> }));
jest.mock('../../components/Modal/Modal', () => ({ Modal: ({ children }) => <div>{children}</div> }));
jest.mock('../../utils/helpers', () => ({ ...jest.requireActual('../../utils/helpers'), absoluteURL: path => path }));

beforeEach(() => {
  jest.resetAllMocks();
  localStorage.clear();
  mockApi.projectCopyDefaults.mockResolvedValue({ storage_title: 'Original S3', source_storage: { bucket: 'source', prefix: 'media', aws_access_key_id: 'fixture-ak', aws_secret_access_key: 'fixture-secret' } });
  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [] });
});

test('queues a crop on Label Studio without a worker address or token', async () => {
  mockApi.createProjectCopy.mockResolvedValue({ error: 'temporarily unavailable' });
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByLabelText('Bucket').value).toBe('source'));
  fireEvent.change(screen.getByLabelText('x1'), { target: { value: '1280' } });
  fireEvent.change(screen.getByLabelText('y1'), { target: { value: '720' } });
  fireEvent.change(screen.getByLabelText('Bucket'), { target: { value: 'target-bucket' } });
  fireEvent.click(screen.getByText('开始复制'));
  await waitFor(() => expect(mockApi.createProjectCopy).toHaveBeenCalledTimes(1));
  const [params, { body }] = mockApi.createProjectCopy.mock.calls[0];

  expect(params).toEqual({ pk: 12 });
  expect(body.worker_address).toBeUndefined();
  expect(screen.queryByLabelText('worker_address')).toBeNull();
  expect(body.crop).toEqual({ x0: 0, y0: 0, x1: 1280, y1: 720 });
  expect(body.source_storage.bucket).toBe('target-bucket');
  expect(body.label_studio_token).toBeUndefined();
  await screen.findByText('temporarily unavailable');
  fireEvent.click(screen.getByText('开始复制'));
  await waitFor(() => expect(mockApi.createProjectCopy).toHaveBeenCalledTimes(2));
  expect(mockApi.createProjectCopy.mock.calls[1][1].body.idempotency_key).toBe(body.idempotency_key);
});

test('opens a historical job and displays its stage and target project', async () => {
  const job = { id: 'job', new_project_name: 'Copied', status: 'copying', worker_ready: true, phase: 'cropping', total: 2,
    completed: 1, failed: 0, progress: 50, file_progress: 0.2, current_task: 9, created: 1,
    target_project: 20, crop: { x0: 0, y0: 0, x1: 100, y1: 80 }, errors: [] };

  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [job] });
  mockApi.projectCopyJob.mockResolvedValue(job);
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
  fireEvent.click(await screen.findByRole('button', { name: '详情：Copied' }));
  await screen.findByText('裁剪中 · task 9');
  expect(screen.getByLabelText('项目复制进度').value).toBe(50);
  expect(screen.getByRole('link', { name: /打开新项目/ }).getAttribute('href')).toBe('/projects/20/data');
});


test('expires Ready after 30 seconds even if the next status request hangs', async () => {
  jest.useFakeTimers();
  try {
    mockApi.projectCopyJobs.mockResolvedValueOnce({ jobs: [], worker: {
      ready: true, last_heartbeat: 100, server_time: 100, timeout: 30, interval: 10,
    } }).mockImplementation(() => new Promise(() => {}));
    render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByLabelText('Worker 状态').textContent).toBe('Ready');
    act(() => { jest.advanceTimersByTime(31000); });
    expect(screen.getByLabelText('Worker 状态').textContent).toBe('not Ready');
  } finally {
    jest.useRealTimers();
  }
});

test('shows queue errors and preserves configuration when switching history', async () => {
  mockApi.projectCopyJobs.mockResolvedValue({ error: 'Unavailable', response: { detail: '服务暂时不可用' } });
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('新项目名称'), { target: { value: 'My copy' } });
  fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
  expect((await screen.findByRole('alert')).textContent).toContain('服务暂时不可用');
  fireEvent.click(screen.getByRole('button', { name: '复制配置' }));
  expect(screen.getByLabelText('新项目名称').value).toBe('My copy');
});

const failedCopy = {
  id: 'failed-job', new_project_name: 'Failed copy', status: 'fail', phase: 'failed',
  total: 0, completed: 0, failed: 0, progress: 0, created: 1,
  crop: { x0: 0, y0: 0, x1: 100, y1: 80 }, errors: [],
  error: 'NoCredentialsError: operation failed; verify connectivity, credentials and service configuration',
};

test('polls failed job details without treating the job error as a history API failure', async () => {
  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [{ ...failedCopy, status: 'copying', error: null }] });
  mockApi.projectCopyJob.mockResolvedValue({ ...failedCopy, $meta: { status: 200 } });
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
  fireEvent.click(await screen.findByRole('button', { name: '详情：Failed copy' }));
  await screen.findByText(/worker 未找到 S3 凭证/);
  expect(screen.queryByText('暂时无法读取复制记录')).toBeNull();
  const waiting = { ...failedCopy, status: 'waiting', error: null, phase: 'queued' };

  mockApi.retryProjectCopy.mockResolvedValue(waiting);
  mockApi.projectCopyJob.mockResolvedValue(waiting);
  fireEvent.click(screen.getByRole('button', { name: '重试失败任务' }));
  await screen.findByText('waiting');
  expect(mockApi.retryProjectCopy).toHaveBeenCalledWith({ pk: 12, job_id: failedCopy.id }, { body: {} });
  expect(screen.queryByText(/worker 未找到 S3 凭证/)).toBeNull();
});

test('an idempotent submission returning a failed job still opens its history', async () => {
  mockApi.createProjectCopy.mockResolvedValue({ ...failedCopy, $meta: { status: 202 } });
  mockApi.projectCopyJob.mockResolvedValue(failedCopy);
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByLabelText('Bucket').value).toBe('source'));
  fireEvent.change(screen.getByLabelText('x1'), { target: { value: '100' } });
  fireEvent.change(screen.getByLabelText('y1'), { target: { value: '80' } });
  fireEvent.change(screen.getByLabelText('Bucket'), { target: { value: 'destination' } });
  fireEvent.click(screen.getByRole('button', { name: '开始复制' }));
  await screen.findByRole('button', { name: '重试失败任务' });
  expect(screen.getByRole('button', { name: /复制历史/, hidden: true }).getAttribute('aria-pressed')).toBe('true');
  expect(screen.queryByText('暂时无法读取复制记录')).toBeNull();
});

test('keeps an API failure notice stable while the next detail poll is pending', async () => {
  jest.useFakeTimers();
  try {
    mockApi.projectCopyJobs.mockResolvedValue({ jobs: [failedCopy] });
    mockApi.projectCopyJob.mockResolvedValue({ error: 'Service Unavailable', response: { detail: '服务暂时不可用' } });
    render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
    fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole('button', { name: '详情：Failed copy' }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByRole('alert').textContent).toContain('服务暂时不可用');
    let finishDetail;

    mockApi.projectCopyJob.mockImplementationOnce(() => new Promise(resolve => { finishDetail = resolve; }));
    await act(async () => { jest.advanceTimersByTime(3000); });
    // A successful list refresh must not hide the existing detail-error notice before that request completes.
    expect(screen.getByRole('alert').textContent).toContain('服务暂时不可用');
    await act(async () => { finishDetail(failedCopy); });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(mockApi.retryProjectCopy).not.toHaveBeenCalled();
    expect(mockApi.createProjectCopy).not.toHaveBeenCalled();
  } finally {
    jest.useRealTimers();
  }
});

test('prefills credentials and requires a real storage change, including after reverting', async () => {
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByLabelText('Bucket').value).toBe('source'));
  expect(screen.getByLabelText('Access key ID').value).toBe('fixture-ak');
  expect(screen.getByLabelText('Secret access key').value).toBe('fixture-secret');
  expect(screen.getByLabelText('Secret access key').type).toBe('password');
  const start = screen.getByRole('button', { name: '开始复制' });

  expect(start.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('新项目名称'), { target: { value: 'New name' } });
  expect(start.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Prefix'), { target: { value: ' /media/ ' } });
  expect(start.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Prefix'), { target: { value: 'cropped' } });
  expect(start.disabled).toBe(false);
  fireEvent.change(screen.getByLabelText('Prefix'), { target: { value: 'media' } });
  expect(start.disabled).toBe(true);
  fireEvent.submit(document.getElementById('project-copy-form'));
  expect(mockApi.createProjectCopy).not.toHaveBeenCalled();
  expect(localStorage.length).toBe(0);
});

test('sorts history newest first, shows operator and opens a separate detail dialog', async () => {
  const older = { ...failedCopy, id: 'old', created: 1, new_project_name: 'Old copy', operator: { name: 'Alice' } };
  const newer = { ...failedCopy, id: 'new', created: 2, new_project_name: 'New copy', operator: { name: 'Bob' }, can_retry: false };

  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [older, newer] });
  mockApi.projectCopyJob.mockResolvedValue(newer);
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
  await screen.findByRole('table', { name: '复制历史列表' });
  const rows = screen.getAllByRole('row');

  expect(rows[1].textContent).toContain('New copy');
  expect(rows[1].textContent).toContain('Bob');
  expect(rows[2].textContent).toContain('Alice');
  expect(screen.queryByLabelText('项目复制进度')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: '详情：New copy' }));
  await screen.findByRole('dialog', { name: '复制详情' });
  expect(screen.queryByRole('button', { name: '重试失败任务' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: '返回历史' }));
  expect(screen.queryByRole('dialog', { name: '复制详情' })).toBeNull();
  expect(screen.getAllByRole('row')).toHaveLength(3);
  await act(async () => { await Promise.resolve(); });
});

test('defaults failure blocks submission but history remains accessible', async () => {
  mockApi.projectCopyDefaults.mockResolvedValue({ error: 'Forbidden' });
  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [failedCopy] });
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
  await screen.findByText('Forbidden');
  expect(screen.getByRole('button', { name: '开始复制' }).disabled).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: /复制历史/ }));
  await screen.findByRole('button', { name: '详情：Failed copy' });
});
