"""Spatial transforms in Label Studio's 0..100 coordinate system."""
import copy
import math

from defusedxml import ElementTree


def media_field(label_config):
    root = ElementTree.fromstring(label_config)
    media = [tag for tag in root.iter() if tag.tag in ('Image', 'Video')]
    if len(media) != 1:
        raise ValueError('Copy requires exactly one Image or Video field in the labeling configuration')
    tag = media[0]
    value = tag.get('value', '')
    if not value.startswith('$') or not value[1:] or '.' in value[1:]:
        raise ValueError('The media value must reference a top-level task field, for example $video')
    return {'name': tag.get('name'), 'key': value[1:], 'kind': tag.tag.lower()}


def number(value):
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('Non-finite box coordinate')
    return value


def box(value, width, height, crop):
    if number(value.get('rotation', 0)) % 360:
        raise ValueError('Rotated bounding boxes are not supported')
    x, y, w, h = (number(value[k]) for k in ('x', 'y', 'width', 'height'))
    if w < 0 or h < 0:
        raise ValueError('Negative box dimensions')
    left, top = max(x * width / 100, crop['x0']), max(y * height / 100, crop['y0'])
    right = min((x + w) * width / 100, crop['x1'])
    bottom = min((y + h) * height / 100, crop['y1'])
    if right <= left or bottom <= top:
        return None
    cw, ch = crop['x1'] - crop['x0'], crop['y1'] - crop['y0']
    return dict(x=100 * (left - crop['x0']) / cw, y=100 * (top - crop['y0']) / ch,
                width=100 * (right - left) / cw, height=100 * (bottom - top) / ch, rotation=0)


def video_sequence(sequence, width, height, crop):
    """Add keyframes at each clipping breakpoint, preserving discrete-frame interpolation.

    Clamp/intersection is piecewise linear. Samples immediately before/after every
    boundary crossing suffice; expanding long videos to one JSON box per frame does not.
    """
    if not sequence:
        return []
    sequence = sorted(copy.deepcopy(sequence), key=lambda p: p['frame'])
    if any(int(p['frame']) != p['frame'] or p['frame'] < 0 for p in sequence):
        raise ValueError('Video keyframes must have non-negative integer frame numbers')
    if len({p['frame'] for p in sequence}) != len(sequence):
        raise ValueError('Duplicate video keyframe')
    output = []

    def emit(point):
        clipped = box(point, width, height, crop)
        point['enabled'] = point.get('enabled', True) and clipped is not None
        point.update(clipped or dict(x=0, y=0, width=0, height=0, rotation=0))
        output.append(point)

    for index, first in enumerate(sequence):
        box(first, width, height, crop)  # also validate invisible / last keyframes
        emit(copy.deepcopy(first))
        if index + 1 == len(sequence):
            continue
        last = sequence[index + 1]
        gap = last['frame'] - first['frame']
        if gap <= 1:
            continue
        frames = set()
        # All changes of slope, including enter/leave events, happen here.
        for dimension, size, low, high in [('x', width, crop['x0'], crop['x1']),
                                            ('y', height, crop['y0'], crop['y1'])]:
            extent = 'width' if dimension == 'x' else 'height'
            for edge in (False, True):
                a = (number(first[dimension]) + (number(first[extent]) if edge else 0)) * size / 100
                b = (number(last[dimension]) + (number(last[extent]) if edge else 0)) * size / 100
                if a == b:
                    continue
                for boundary in (low, high):
                    frame = first['frame'] + (boundary - a) * gap / (b - a)
                    if first['frame'] <= frame <= last['frame']:
                        frames.update((math.floor(frame) - 1, math.floor(frame), math.ceil(frame), math.ceil(frame) + 1))
        for frame in sorted(f for f in frames if first['frame'] < f < last['frame']):
            ratio = (frame - first['frame']) / gap
            point = dict(first, frame=frame)
            for key in ('x', 'y', 'width', 'height', 'rotation', 'time'):
                if key in first or key in last:
                    point[key] = number(first.get(key, 0)) + ratio * (number(last.get(key, 0)) - number(first.get(key, 0)))
            emit(point)
    return output if any(p.get('enabled', True) for p in output) else []


def transform_results(results, width, height, crop):
    output, removed = [], set()
    rectangles = {'rectangle', 'rectanglelabels', 'videorectangle'}
    metadata = {'labels', 'choices', 'textarea', 'rating', 'number', 'relation'}
    for original in results or []:
        item = copy.deepcopy(original)
        kind, value = item.get('type'), item.get('value', {})
        if kind not in rectangles | metadata:
            raise ValueError('Only rectangular spatial annotations are supported: ' + str(kind))
        if kind in rectangles:
            if number(item.get('image_rotation', 0)) % 360:
                raise ValueError('Annotations with image rotation are not supported')
            if kind == 'videorectangle':
                value['sequence'] = video_sequence(value.get('sequence', []), width, height, crop)
                valid = bool(value['sequence'])
            else:
                # Prefer decoded dimensions; stale original_width metadata must not silently shift boxes.
                for key, actual in [('original_width', width), ('original_height', height)]:
                    if item.get(key) and item[key] != actual:
                        raise ValueError('Annotation dimensions differ from the decoded media')
                clipped = box(value, width, height, crop)
                valid = clipped is not None
                if valid:
                    value.update(clipped)
            if not valid:
                if item.get('id') is not None:
                    removed.add(item['id'])
                continue
            if kind != 'videorectangle' or 'original_width' in item:
                item['original_width'] = crop['x1'] - crop['x0']
                item['original_height'] = crop['y1'] - crop['y0']
        output.append(item)
    return [item for item in output if item.get('id') not in removed and
            not (item.get('type') == 'relation' and
                 (item.get('from_id') in removed or item.get('to_id') in removed))]


def transform_task(task, width, height, crop):
    task = copy.deepcopy(task)

    def prediction_snapshot(value):
        if isinstance(value, dict):
            if 'result' in value:
                value['result'] = transform_results(value['result'], width, height, crop)
        elif isinstance(value, list):
            for child in value:
                prediction_snapshot(child)

    for group in ('annotations', 'predictions', 'drafts'):
        for item in task.get(group, []):
            item['result'] = transform_results(item.get('result'), width, height, crop)
            prediction_snapshot(item.get('prediction'))
    return task
