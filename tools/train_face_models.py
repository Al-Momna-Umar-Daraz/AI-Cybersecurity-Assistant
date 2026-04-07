from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from PIL import Image, ImageOps
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.neighbors import KNeighborsClassifier, NearestNeighbors
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC


BASE_DIR = Path(__file__).resolve().parents[1]
CURATED_DIR = BASE_DIR / 'data' / 'curated'
MODEL_DIR = BASE_DIR / 'data' / 'models'
EMOTION_DIR = CURATED_DIR / 'emotion_full_v2'
LFW_DIR = CURATED_DIR / 'lfw_full_v2'


def image_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in {'.png', '.jpg', '.jpeg', '.webp'}
    )


def load_image_vector(path: Path, size: tuple[int, int]) -> np.ndarray:
    image = Image.open(path)
    image = ImageOps.exif_transpose(image).convert('L')
    image = ImageOps.fit(image, size, method=Image.Resampling.LANCZOS)
    return np.asarray(image, dtype=np.float32).reshape(-1) / 255.0


def load_labeled_dataset(root: Path, size: tuple[int, int]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    vectors = []
    labels = []
    paths = []
    for class_dir in sorted([p for p in root.iterdir() if p.is_dir()]):
        for img_path in image_files(class_dir):
            try:
                vector = load_image_vector(img_path, size)
            except Exception:
                continue
            vectors.append(vector)
            labels.append(class_dir.name)
            paths.append(str(img_path.relative_to(BASE_DIR)).replace('\\', '/'))
    return np.asarray(vectors, dtype=np.float32), np.asarray(labels), paths


def train_emotion_model() -> dict:
    x, y, paths = load_labeled_dataset(EMOTION_DIR, (48, 48))
    if x.shape[0] < 20:
        raise RuntimeError('Emotion curated dataset is too small to train.')

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    model = Pipeline(
        [
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=min(50, x.shape[0] - 1), random_state=42)),
            ('clf', KNeighborsClassifier(n_neighbors=3, metric='cosine')),
        ]
    )
    scores = cross_val_score(model, x, y, cv=cv, scoring='accuracy')
    model.fit(x, y)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / 'emotion_model.joblib')

    counts = {}
    for label in y:
        counts[label] = counts.get(label, 0) + 1

    return {
        'dataset_dir': str(EMOTION_DIR.relative_to(BASE_DIR)).replace('\\', '/'),
        'samples': int(x.shape[0]),
        'labels': sorted(counts.keys()),
        'class_counts': counts,
        'cv_accuracy_mean': round(float(scores.mean()), 4),
        'cv_accuracy_std': round(float(scores.std()), 4),
        'model_path': 'data/models/emotion_model.joblib',
        'feature_shape': int(x.shape[1]),
        'source_examples': paths[:5],
    }


def train_lfw_models() -> dict:
    x, y, paths = load_labeled_dataset(LFW_DIR, (64, 64))
    if x.shape[0] < 40:
        raise RuntimeError('LFW curated dataset is too small to train.')

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(y)
    x_train, x_test, y_train, y_test, path_train, path_test = train_test_split(
        x,
        encoded,
        paths,
        test_size=0.2,
        random_state=42,
        stratify=encoded,
    )

    classifier = Pipeline(
        [
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=min(100, x_train.shape[0] - 1), random_state=42)),
            ('clf', SVC(C=8.0, kernel='rbf', gamma='scale')),
        ]
    )
    classifier.fit(x_train, y_train)
    pred = classifier.predict(x_test)
    acc = accuracy_score(y_test, pred)

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x)
    pca = PCA(n_components=min(120, x.shape[0] - 1), random_state=42)
    x_proj = pca.fit_transform(x_scaled)
    nn_index = NearestNeighbors(n_neighbors=5, metric='cosine')
    nn_index.fit(x_proj)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier, MODEL_DIR / 'lfw_identity_classifier.joblib')
    joblib.dump({'scaler': scaler, 'pca': pca, 'index': nn_index}, MODEL_DIR / 'lfw_identity_index.joblib')

    gallery = []
    for idx, (label_id, rel_path) in enumerate(zip(encoded.tolist(), paths)):
        gallery.append(
            {
                'person': str(encoder.inverse_transform([label_id])[0]),
                'image_path': rel_path,
                'vector_index': idx,
            }
        )
    (MODEL_DIR / 'lfw_identity_gallery.json').write_text(
        json.dumps(gallery, indent=2, ensure_ascii=True),
        encoding='utf-8',
    )

    return {
        'dataset_dir': str(LFW_DIR.relative_to(BASE_DIR)).replace('\\', '/'),
        'samples': int(x.shape[0]),
        'people': int(len(encoder.classes_)),
        'holdout_accuracy': round(float(acc), 4),
        'classifier_path': 'data/models/lfw_identity_classifier.joblib',
        'index_path': 'data/models/lfw_identity_index.joblib',
        'gallery_path': 'data/models/lfw_identity_gallery.json',
        'sample_people': encoder.classes_[:10].tolist(),
        'test_examples': path_test[:5],
    }


def main() -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        'emotion': train_emotion_model(),
        'lfw_identity': train_lfw_models(),
    }
    (MODEL_DIR / 'training_report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=True),
        encoding='utf-8',
    )
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
