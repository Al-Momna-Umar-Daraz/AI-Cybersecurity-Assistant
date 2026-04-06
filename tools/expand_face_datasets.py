from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageEnhance, ImageOps


BASE_DIR = Path(__file__).resolve().parents[1]
EMOTION_DIR = BASE_DIR / 'data' / 'curated' / 'emotion_full_v2'
LFW_DIR = BASE_DIR / 'data' / 'curated' / 'lfw_full_v2'
IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.webp'}
EMOTION_MIN_PER_CLASS = 80
LFW_MIN_PER_PERSON = 35


def image_files(folder: Path) -> list[Path]:
    return sorted([p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES])


def readable_image(path: Path) -> bool:
    try:
        image = Image.open(path)
        image.verify()
        return True
    except Exception:
        return False


def source_seed_files(folder: Path) -> list[Path]:
    return sorted([p for p in image_files(folder) if '_aug_' not in p.stem.lower() and readable_image(p)])


def augment_image(source: Path, index: int) -> Image.Image:
    image = Image.open(source)
    image = ImageOps.exif_transpose(image).convert('RGB')

    mode = index % 6
    if mode == 0:
        image = ImageOps.mirror(image)
    elif mode == 1:
        image = ImageEnhance.Contrast(image).enhance(1.16)
    elif mode == 2:
        image = ImageEnhance.Brightness(image).enhance(1.08)
    elif mode == 3:
        image = ImageEnhance.Sharpness(image).enhance(1.22)
    elif mode == 4:
        image = image.rotate(5, resample=Image.Resampling.BICUBIC)
    else:
        image = image.rotate(-5, resample=Image.Resampling.BICUBIC)
    return image


def next_aug_index(folder: Path) -> int:
    highest = 0
    for file_path in image_files(folder):
        stem = file_path.stem.lower()
        if '_aug_' not in stem:
            continue
        try:
            highest = max(highest, int(stem.rsplit('_aug_', 1)[1]))
        except ValueError:
            continue
    return highest + 1


def expand_folder_groups(root: Path, minimum_per_group: int) -> int:
    groups = [p for p in root.iterdir() if p.is_dir()]
    created = 0
    for group in sorted(groups):
        files = [p for p in image_files(group) if readable_image(p)]
        if not files:
            continue
        seeds = source_seed_files(group) or files
        existing = len(files)
        if existing >= minimum_per_group:
            continue
        current_index = next_aug_index(group)
        need = minimum_per_group - existing
        for i in range(need):
            src = seeds[i % len(seeds)]
            out = group / f'{src.stem}_aug_{current_index:03d}.jpg'
            current_index += 1
            aug = augment_image(src, i)
            aug.save(out, format='JPEG', quality=92, optimize=True)
            created += 1
    return created


def main() -> None:
    if not EMOTION_DIR.exists():
        raise FileNotFoundError(f'Missing folder: {EMOTION_DIR}')
    if not LFW_DIR.exists():
        raise FileNotFoundError(f'Missing folder: {LFW_DIR}')

    emotion_added = expand_folder_groups(EMOTION_DIR, EMOTION_MIN_PER_CLASS)
    lfw_added = expand_folder_groups(LFW_DIR, LFW_MIN_PER_PERSON)

    emotion_total = sum(1 for p in EMOTION_DIR.rglob('*') if p.is_file())
    lfw_total = sum(1 for p in LFW_DIR.rglob('*') if p.is_file())

    print(
        {
            'emotion_added': emotion_added,
            'emotion_total': emotion_total,
            'lfw_added': lfw_added,
            'lfw_total': lfw_total,
            'emotion_min_per_class': EMOTION_MIN_PER_CLASS,
            'lfw_min_per_person': LFW_MIN_PER_PERSON,
        }
    )


if __name__ == '__main__':
    main()
