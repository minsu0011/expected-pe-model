from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
    canonical_csv_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.channel import (
    write_message,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
    PUBLIC_SURFACE_HEADERS,
    TRUTH_COLUMNS,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
    public_generation,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
    HELDOUT_SEEDS,
    HELDOUT_PUBLIC_CHANNEL_SCHEMA,
    PUBLIC_SOURCE_NAMES,
    SOURCE_ROWS_PER_TASK,
    HeldoutAuthorityError,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation import (
    heldout_tasks,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.protected_generation import (
    synthetic_channel_bytes,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction_execution import (
    numeric_child_environment,
)


def _frame(rows: int, *, column: str) -> pd.DataFrame:
    return pd.DataFrame({column: np.arange(rows, dtype=np.int64)})


def test_live_heldout_seed_commitment_is_exact() -> None:
    assert HELDOUT_SEEDS == (7789, 7793, 7817, 7823, 7829)
    raw = json.dumps(
        {"locked_seeds": list(HELDOUT_SEEDS)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    assert hashlib.sha256(raw).hexdigest() == (
        "517acd3b8e033dc10087a1ae8ff8ef237a00b8c193ab758796860ff2dc575ede"
    )


def _heterogeneous_generator(
    *, eps_rows: int = 29, corporate_action_rows: int = 0
) -> SimpleNamespace:
    public = {
        "price": _frame(1_800, column="price_value"),
        "benchmark": _frame(1_800, column="benchmark_value"),
        "eps_events": _frame(eps_rows, column="eps_value"),
        "public_factors": _frame(3_600, column="factor_value"),
        "corporate_actions": _frame(corporate_action_rows, column="action_value"),
    }
    truth = pd.DataFrame(
        {name: np.arange(SOURCE_ROWS_PER_TASK, dtype=np.float64) for name in TRUTH_COLUMNS}
    )
    protected = {
        "truth": truth,
        "latent_events": _frame(SOURCE_ROWS_PER_TASK, column="state"),
    }
    return SimpleNamespace(public=public, evaluator_only=protected)


def test_bce_numeric_worker_receives_its_exact_frozen_spawn_environment() -> None:
    from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.contracts import (
        RESOURCE_POLICY,
    )

    bce = numeric_child_environment("bce")
    c4 = numeric_child_environment("c4")
    assert {key: bce.get(key) for key in RESOURCE_POLICY.environment} == (
        RESOURCE_POLICY.environment
    )
    assert "HIP_VISIBLE_DEVICES" not in c4
    assert "ROCR_VISIBLE_DEVICES" not in c4
    with pytest.raises(HeldoutAuthorityError, match="environment lane"):
        numeric_child_environment("other")


@pytest.mark.parametrize(
    ("eps_rows", "corporate_action_rows"),
    ((29, 0), (17, 3)),
)
def test_protected_generation_accepts_natural_public_geometry(
    tmp_path: Path,
    eps_rows: int,
    corporate_action_rows: int,
) -> None:
    task = heldout_tasks()[0]
    pass_root = tmp_path / "pass_1"
    pass_root.mkdir()

    def generator(_dgp: str, *, master_seed: int) -> SimpleNamespace:
        assert master_seed == task.data_seed
        return _heterogeneous_generator(
            eps_rows=eps_rows,
            corporate_action_rows=corporate_action_rows,
        )

    channel = synthetic_channel_bytes(
        task=task,
        replay_pass=1,
        vault_pass_root=pass_root,
        expected_first_protected_hashes=None,
        generator=generator,
        project_root=tmp_path,
    )
    assert channel
    assert (pass_root / f"seed_{task.data_seed}" / "dgp_A" / "truth.csv").is_file()


def test_protected_generation_rejects_bad_protected_geometry(
    tmp_path: Path,
) -> None:
    task = heldout_tasks()[0]
    pass_root = tmp_path / "pass_1"
    pass_root.mkdir()

    def generator(_dgp: str, *, master_seed: int) -> SimpleNamespace:
        generated = _heterogeneous_generator()
        generated.evaluator_only["latent_events"] = _frame(1_799, column="state")
        return generated

    with pytest.raises(HeldoutAuthorityError, match="task row geometry"):
        synthetic_channel_bytes(
            task=task,
            replay_pass=1,
            vault_pass_root=pass_root,
            expected_first_protected_hashes=None,
            generator=generator,
            project_root=tmp_path,
        )


def test_protected_generation_rejects_duplicate_public_columns(
    tmp_path: Path,
) -> None:
    task = heldout_tasks()[0]
    pass_root = tmp_path / "pass_1"
    pass_root.mkdir()

    def generator(_dgp: str, *, master_seed: int) -> SimpleNamespace:
        generated = _heterogeneous_generator()
        generated.public["eps_events"] = pd.DataFrame(
            np.ones((29, 2)), columns=["duplicate", "duplicate"]
        )
        return generated

    with pytest.raises(HeldoutAuthorityError, match="public frame schema"):
        synthetic_channel_bytes(
            task=task,
            replay_pass=1,
            vault_pass_root=pass_root,
            expected_first_protected_hashes=None,
            generator=generator,
            project_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("eps_rows", "corporate_action_rows"),
    ((29, 0), (17, 3)),
)
def test_public_replay_accepts_heterogeneous_raw_geometry(
    monkeypatch: pytest.MonkeyPatch,
    eps_rows: int,
    corporate_action_rows: int,
) -> None:
    task = heldout_tasks()[0]
    generated = _heterogeneous_generator(
        eps_rows=eps_rows,
        corporate_action_rows=corporate_action_rows,
    )
    raw_frames = {name: canonical_csv_bytes(generated.public[name]) for name in PUBLIC_SOURCE_NAMES}
    stream = io.BytesIO()
    write_message(
        stream,
        {
            "schema_version": HELDOUT_PUBLIC_CHANNEL_SCHEMA,
            "stage": "HELDOUT_CERTIFICATION",
            "task_ordinal": task.task_ordinal,
            "data_seed": task.data_seed,
            "seed_alias": task.seed_alias,
            "dgp_id": task.dgp_id,
            "replay_pass": 1,
            "rows": SOURCE_ROWS_PER_TASK,
            "protected_path_included": False,
            "protected_value_included": False,
        },
        raw_frames,
    )
    stream.seek(0)

    dates = pd.date_range("2030-01-01", periods=1_800, freq="D").strftime("%Y-%m-%d")
    canonical = pd.DataFrame(
        {
            "date": dates,
            "symbol": "DGP_ISSUER",
            **{f"canonical_{ordinal:03d}": 0.0 for ordinal in range(148)},
        }
    )
    overlay = pd.DataFrame(
        {
            "date": dates,
            **{f"overlay_{ordinal:03d}": 0.0 for ordinal in range(253)},
        }
    )
    replay = SimpleNamespace(
        canonical_raw=b"canonical",
        overlay_raw=b"overlay",
        normalized_receipt={"status": "SYNTHETIC_REPLAY"},
    )
    monkeypatch.setattr(public_generation, "_require_no_protected_imports", lambda: None)
    monkeypatch.setattr(public_generation, "run_public_replay", lambda *args, **kwargs: replay)
    monkeypatch.setattr(
        public_generation,
        "parse_public_outputs",
        lambda *_args, **_kwargs: (canonical, overlay),
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1 import (
        raw_header,
    )

    monkeypatch.setattr(
        raw_header,
        "raw_header_sha256",
        lambda raw: PUBLIC_SURFACE_HEADERS[
            "canonical150.csv" if raw == b"canonical" else "v04_overlay.csv"
        ]["header_raw_sha256"],
    )
    result = public_generation.replay_public_channel(
        task=task,
        replay_pass=1,
        stream=stream,
        expected_inventory={},
        expected_child_runtime={},
    )
    assert result.receipt["status"] == "PASS_PUBLIC_ONLY_REPLAY_PRETRUTH"
    assert tuple(result.public_frame_raw_sha256) == PUBLIC_SOURCE_NAMES
    assert result.public_frame_rows == {
        name: len(generated.public[name]) for name in PUBLIC_SOURCE_NAMES
    }
    assert [len(generated.public[name]) for name in PUBLIC_SOURCE_NAMES] == [
        1_800,
        1_800,
        eps_rows,
        3_600,
        corporate_action_rows,
    ]
