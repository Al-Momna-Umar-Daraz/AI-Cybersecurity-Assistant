from __future__ import annotations

import json
import os
import stat
import shutil
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
CURATED_DIR = BASE_DIR / 'data' / 'curated'
EMOTION_TARGET = CURATED_DIR / 'emotion_full_v2'
LFW_TARGET = CURATED_DIR / 'lfw_full_v2'
IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.webp'}
EMOTION_LABELS = {'angry', 'disgust', 'fear', 'happy', 'neutral', 'sad', 'surprise'}
EMOTION_SOURCES = [
    BASE_DIR / 'data' / 'datasets' / 'emotion_detection',
    BASE_DIR / 'data' / 'archive (1)',
    BASE_DIR / 'data' / 'curated' / 'emotion_100',
]
LFW_SOURCES = [
    BASE_DIR / 'data' / 'datasets' / 'lfw_identity',
    BASE_DIR / 'deploy' / 'archive',
    BASE_DIR / 'data' / 'curated' / 'lfw_200',
]


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onerror=handle_remove_readonly)
    path.mkdir(parents=True, exist_ok=True)


def handle_remove_readonly(func, target, exc_info) -> None:
    os.chmod(target, stat.S_IWRITE)
    func(target)


def image_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    return sorted(
        p for p in path.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES
    )


def unique_copy_name(src: Path) -> str:
    safe_parent = src.parent.name.replace(' ', '_')
    safe_stem = src.stem.replace(' ', '_')
    return f'{safe_parent}__{safe_stem}{src.suffix.lower()}'


def copy_group_files(files: list[Path], target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    used_names: set[str] = set()
    for index, src in enumerate(files, start=1):
        base_name = unique_copy_name(src)
        candidate = base_name
        while candidate in used_names or (target_dir / candidate).exists():
            candidate = f'{Path(base_name).stem}_{index:04d}{Path(base_name).suffix}'
            index += 1
        used_names.add(candidate)
        dest = target_dir / candidate
        shutil.copy2(src, dest)
        copied.append(str(dest.relative_to(BASE_DIR)).replace('\\', '/'))
    return copied


def collect_emotion_sources() -> dict[str, list[Path]]:
    buckets = {label: [] for label in sorted(EMOTION_LABELS)}
    seen: set[Path] = set()
    for root in EMOTION_SOURCES:
        if not root.exists():
            continue
        for folder in root.rglob('*'):
            if not folder.is_dir():
                continue
            label = folder.name.lower().strip()
            if label not in buckets:
                continue
            for image_path in image_files(folder):
                resolved = image_path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                buckets[label].append(image_path)
    return {label: sorted(files) for label, files in buckets.items() if files}


def collect_lfw_sources() -> dict[str, list[Path]]:
    buckets: dict[str, list[Path]] = {}
    seen: set[Path] = set()
    for root in LFW_SOURCES:
        if not root.exists():
            continue
        for folder in root.rglob('*'):
            if not folder.is_dir():
                continue
            files = image_files(folder)
            if len(files) < 2:
                continue
            name = folder.name.strip()
            if not name or name.lower() in {'archive', 'lfw-deepfunneled', 'lfw_identity'}:
                continue
            bucket = buckets.setdefault(name, [])
            for image_path in files:
                resolved = image_path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                bucket.append(image_path)
    return {label: sorted(files) for label, files in buckets.items() if files}


def build_emotion_full_dataset() -> dict:
    groups = collect_emotion_sources()
    if not groups:
        raise FileNotFoundError('No emotion image folders were found.')
    clean_dir(EMOTION_TARGET)
    manifest = {'dataset': 'emotion_full', 'classes': {}}
    for label, files in groups.items():
        copied = copy_group_files(files, EMOTION_TARGET / label)
        manifest['classes'][label] = {'count': len(copied), 'files': copied}
    return manifest


def build_lfw_full_dataset() -> dict:
    groups = collect_lfw_sources()
    if not groups:
        raise FileNotFoundError('No face gallery folders were found.')
    clean_dir(LFW_TARGET)
    manifest = {'dataset': 'lfw_full', 'people': {}}
    for label, files in sorted(groups.items()):
        copied = copy_group_files(files, LFW_TARGET / label)
        manifest['people'][label] = {'count': len(copied), 'files': copied}
    return manifest


def main() -> None:
    CURATED_DIR.mkdir(parents=True, exist_ok=True)
    emotion_manifest = build_emotion_full_dataset()
    lfw_manifest = build_lfw_full_dataset()
    summary = {
        'emotion_total': sum(item['count'] for item in emotion_manifest['classes'].values()),
        'lfw_total': sum(item['count'] for item in lfw_manifest['people'].values()),
        'emotion_classes': len(emotion_manifest['classes']),
        'lfw_people': len(lfw_manifest['people']),
        'emotion_dataset': 'data/curated/emotion_full_v2',
        'lfw_dataset': 'data/curated/lfw_full_v2',
    }
    (CURATED_DIR / 'emotion_full_manifest.json').write_text(
        json.dumps(emotion_manifest, indent=2, ensure_ascii=True),
        encoding='utf-8',
    )
    (CURATED_DIR / 'lfw_full_manifest.json').write_text(
        json.dumps(lfw_manifest, indent=2, ensure_ascii=True),
        encoding='utf-8',
    )
    (CURATED_DIR / 'summary.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=True),
        encoding='utf-8',
    )
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
