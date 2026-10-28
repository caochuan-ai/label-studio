import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
from fractions import Fraction
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from PIL import Image, ImageOps


MAX_BYTES = int(os.getenv('MAX_MEDIA_BYTES', str(20 * 1024 ** 3)))
TIMEOUT = int(os.getenv('MEDIA_TIMEOUT_SECONDS', '21600'))
MIN_FREE_BYTES = int(os.getenv('MIN_FREE_BYTES', str(1024 ** 3)))
MAX_FRAME_PIXELS = int(os.getenv('MAX_FRAME_PIXELS', '16777216'))


class Interrupted(Exception):
    pass


def check_disk(directory, required=0):
    if shutil.disk_usage(directory).free < MIN_FREE_BYTES + required:
        raise ValueError('Insufficient temporary disk space')


def download(url, path, client, progress, stop):
    url = urljoin(client.base + '/', url)
    start = time.monotonic()
    with requests.Session() as session:
        session.trust_env = False
        for _ in range(6):
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
                raise ValueError('Media must be an HTTP(S) or resolvable S3 URL')
            if (parsed.scheme, parsed.netloc) != (urlparse(client.base).scheme, urlparse(client.base).netloc):
                for address in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):
                    ip = ipaddress.ip_address(address[4][0])
                    if ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                        raise ValueError('Media URL resolves to a disallowed address')
                headers = {}
            else:
                headers = {'Authorization': 'Token ' + client.token}
            response = session.get(url, headers=headers, stream=True, timeout=(10, 60), allow_redirects=False)
            if response.is_redirect:
                location = response.headers.get('Location', '')
                response.close()
                url = urljoin(url, location)
                continue
            with response:
                if not response.ok:
                    raise RuntimeError('Media download returned HTTP ' + str(response.status_code))
                total = int(response.headers.get('Content-Length') or 0)
                if total > MAX_BYTES:
                    raise ValueError('Media exceeds MAX_MEDIA_BYTES')
                check_disk(path.parent, total)
                size = 0
                with path.open('wb') as output:
                    for chunk in response.iter_content(1024 * 1024):
                        if stop.is_set():
                            raise Interrupted()
                        size += len(chunk)
                        if size > MAX_BYTES or time.monotonic() - start > TIMEOUT:
                            raise ValueError('Media download exceeds size/time limit')
                        check_disk(path.parent)
                        output.write(chunk)
                        progress(min(size / total, 1) if total else 0)
                if total and size != total:
                    raise ValueError('Incomplete media download')
                return
        raise ValueError('Too many media redirects')


def probe(path, count=False):
    command = ['ffprobe', '-v', 'error', '-threads', '1', '-select_streams', 'v:0', '-show_entries',
               'stream=width,height,avg_frame_rate,duration,nb_frames,nb_read_frames:stream_tags=rotate:stream_side_data=rotation:format=duration',
               '-of', 'json']
    if count:
        command += ['-count_frames']
    result = subprocess.run(command + [str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=True)
    data = json.loads(result.stdout)
    if not data.get('streams'):
        raise ValueError('No video stream')
    stream = data['streams'][0]
    width, height = stream['width'], stream['height']
    rotation = int(stream.get('tags', {}).get('rotate', 0))
    for side in stream.get('side_data_list', []):
        rotation = int(side.get('rotation', rotation))
    if rotation % 90:
        raise ValueError('Only video rotation in multiples of 90 degrees is supported')
    if rotation % 180:
        width, height = height, width
    fps_string = stream.get('avg_frame_rate', '0/1')
    fps = float(Fraction(fps_string)) if fps_string != '0/0' else 0
    duration_string = stream.get('duration') or data.get('format', {}).get('duration') or 0
    duration = float(duration_string) if duration_string != 'N/A' else 0
    frames = stream.get('nb_read_frames') or stream.get('nb_frames') or 0
    return {'width': width, 'height': height, 'fps': fps, 'duration': duration,
            'frames': int(frames) if frames != 'N/A' else 0}


def validate_crop(width, height, crop, video=False):
    if not (0 <= crop['x0'] < crop['x1'] <= width and 0 <= crop['y0'] < crop['y1'] <= height):
        raise ValueError('Crop is outside media dimensions ' + str((width, height)))
    if video and ((crop['x1'] - crop['x0']) % 2 or (crop['y1'] - crop['y0']) % 2):
        raise ValueError('H.264 video crop width and height must be even numbers')


def crop_image(source, destination, crop):
    with Image.open(source) as original:
        if getattr(original, 'n_frames', 1) != 1:
            raise ValueError('Animated/multipage images are not supported')
        if original.width * original.height > MAX_FRAME_PIXELS:
            raise ValueError('Image dimensions exceed MAX_FRAME_PIXELS')
        image = ImageOps.exif_transpose(original)
        width, height = image.size
        validate_crop(width, height, crop)
        check_disk(destination.parent, width * height * 4)
        image.crop((crop['x0'], crop['y0'], crop['x1'], crop['y1'])).save(destination, 'PNG')
    return {'width': width, 'height': height}


def crop_video(source, destination, crop, progress, stop):
    info = probe(source)
    if info['width'] * info['height'] > MAX_FRAME_PIXELS:
        raise ValueError('Video dimensions exceed MAX_FRAME_PIXELS')
    validate_crop(info['width'], info['height'], crop, video=True)
    info = probe(source, count=True)
    progress_file = destination.with_suffix('.progress')
    log_file = destination.with_suffix('.log')
    cw, ch = crop['x1'] - crop['x0'], crop['y1'] - crop['y0']
    command = ['ffmpeg', '-nostdin', '-y', '-v', 'error', '-threads', '1', '-filter_threads', '1',
               '-i', str(source), '-map', '0:v:0', '-map', '0:a?',
               '-vf', f"crop={cw}:{ch}:{crop['x0']}:{crop['y0']}:exact=1",
               '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '18', '-pix_fmt', 'yuv420p',
               '-threads', '1', '-fps_mode', 'passthrough', '-c:a', 'aac', '-movflags', '+faststart',
               '-progress', str(progress_file), str(destination)]
    start = time.monotonic()
    with log_file.open('wb') as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
        try:
            while process.poll() is None:
                if stop.wait(0.5):
                    raise Interrupted()
                if time.monotonic() - start > TIMEOUT:
                    raise ValueError('Video encoding timed out')
                check_disk(destination.parent)
                if destination.exists() and destination.stat().st_size > MAX_BYTES:
                    raise ValueError('Encoded media exceeds MAX_MEDIA_BYTES')
                if progress_file.exists():
                    with progress_file.open('rb') as output:
                        output.seek(max(0, progress_file.stat().st_size - 4096))
                        times = [line.split('=')[1] for line in output.read().decode(errors='ignore').splitlines()
                                 if line.startswith('out_time_us=')]
                    if times and times[-1].lstrip('-').isdigit() and info['duration']:
                        progress(min(float(times[-1]) / 1e6 / info['duration'], 0.99))
            if process.returncode:
                raise ValueError('FFmpeg encoding failed; check codec, crop and input media')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    output = probe(destination, count=True)
    if (output['width'], output['height']) != (cw, ch) or info['frames'] != output['frames']:
        raise ValueError('Encoded dimensions/frame count differ from the requested crop/source')
    if abs(info['duration'] - output['duration']) > max(0.1, 1 / max(info['fps'], 1)):
        raise ValueError('Video duration changed during encoding')
    progress(1)
    return info
