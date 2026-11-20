"""Regression tests for bugs found during the coverage pass.

Each test pins a fix so the bug cannot silently return.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agentx.config import AgentXSettings, save_config


def test_save_config_round_trips_path_fields(tmp_path: Path) -> None:
    """save_config must emit YAML that yaml.safe_load can read back.

    Regression: model_dump() kept Path objects, so yaml.dump wrote
    ``!!python/object/apply:pathlib...`` tags that safe_load rejects.
    """
    cfg = AgentXSettings(data_dir=tmp_path / "data")
    out = tmp_path / "cfg.yaml"
    save_config(out, cfg)

    raw = out.read_text(encoding="utf-8")
    assert "python/object" not in raw

    data = yaml.safe_load(raw)
    assert isinstance(data["data_dir"], str)

    reloaded = AgentXSettings(**data)
    assert Path(reloaded.data_dir) == (tmp_path / "data").resolve()
