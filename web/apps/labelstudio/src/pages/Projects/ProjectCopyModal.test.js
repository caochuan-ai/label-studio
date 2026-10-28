import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProjectCopyModal } from './ProjectCopyModal';

const mockApi = {
  projectCopyJobs: jest.fn(), projectCopyJob: jest.fn(), createProjectCopy: jest.fn(), retryProjectCopy: jest.fn(),
};

jest.mock('../../providers/ApiProvider', () => ({ useAPI: () => ({ api: mockApi }) }));
jest.mock('../../components', () => ({ Button: ({ children, look, size, ...props }) => <button {...props}>{children}</button> }));
jest.mock('../../components/Modal/Modal', () => ({ Modal: ({ children }) => <div>{children}</div> }));
jest.mock('../../utils/helpers', () => ({ ...jest.requireActual('../../utils/helpers'), absoluteURL: path => path }));

beforeEach(() => {
  jest.resetAllMocks();
  localStorage.clear();
  mockApi.projectCopyJobs.mockResolvedValue({ jobs: [] });
});

test('queues a crop on Label Studio without a worker address or token', async () => {
  mockApi.createProjectCopy.mockResolvedValue({ error: 'temporarily unavailable' });
  render(<ProjectCopyModal project={{ id: 12, title: 'Original' }} onClose={() => {}} />);
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
  fireEvent.click(await screen.findByText('Copied'));
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
