import numpy as np

from mini_ids.detectors.ml import combined_scores
from mini_ids.iforest import IsolationForest, c_factor


def test_c_factor():
    assert c_factor(1) == 0
    assert c_factor(2) == 1
    assert 10 < c_factor(256) < 11


def _fit():
    rng = np.random.default_rng(0)
    normal = rng.normal(0, 1, size=(500, 3))
    model = IsolationForest(n_trees=100, sample_size=256, seed=1).fit(normal)
    model.meta = {"min": normal.min(axis=0).tolist(), "max": normal.max(axis=0).tolist()}
    return model, normal, rng.normal(0, 1, size=(50, 3))


def test_outliers_score_higher(tmp_path):
    model, normal, fresh = _fit()
    inliers = model.score_samples(fresh)
    outliers = model.score_samples(np.array([[8, 8, 8], [-9, 0, 7], [6, -7, 5]]))
    assert outliers.min() > inliers.max()
    assert outliers.min() > 0.65

    path = tmp_path / "m.json"
    model.save(path)
    loaded = IsolationForest.load(path)
    np.testing.assert_allclose(loaded.score_samples(normal[:20]), model.score_samples(normal[:20]))


def test_novelty_check_covers_axis_aligned_outlier():
    """Điểm chỉ lệch trên 1 trục là điểm yếu đã biết của Isolation Forest (mỗi nhát cắt chọn
    chiều ngẫu nhiên, 2/3 số nhát rơi vào chiều mà điểm nằm giữa đám đông). Kiểm tra miền bù lại."""
    model, _, fresh = _fit()
    x = np.array([[0.0, 10.0, 0.0]])
    raw = model.score_samples(x)[0]
    combined, oor = combined_scores(model, x)
    assert oor[0].tolist() == [False, True, False]
    assert combined[0] > raw + 0.07
    inlier_combined, inlier_oor = combined_scores(model, fresh)
    assert not inlier_oor.any() or inlier_combined.max() < 0.75
