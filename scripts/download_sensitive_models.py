"""Download pinned-location model snapshots for offline sensitive-data inference."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from huggingface_hub import snapshot_download


MODELS = {
    "gliner": (
        "urchade/gliner_medium-v2.1",
        ["gliner_config.json", "model.safetensors", "README.md"],
    ),
    "bart-large-mnli": (
        "facebook/bart-large-mnli",
        [
            "config.json",
            "merges.txt",
            "model.safetensors",
            "tokenizer.json",
            "tokenizer_config.json",
            "vocab.json",
            "README.md",
        ],
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "models" / "sensitive",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for folder, (repository, allow_patterns) in MODELS.items():
        revision = os.getenv(f"PROMPT_LEAKS_{folder.upper().replace('-', '_')}_REVISION")
        path = snapshot_download(
            repo_id=repository,
            revision=revision,
            local_dir=str(args.output / folder),
            allow_patterns=allow_patterns,
        )
        print(f"Downloaded {repository} to {path}")

    # GLiNER contains its encoder weights, but it still needs the matching
    # DeBERTa tokenizer files. Putting them beside the GLiNER config lets the
    # runtime remain fully local instead of resolving the tokenizer by Hub ID.
    tokenizer_revision = os.getenv("PROMPT_LEAKS_GLINER_TOKENIZER_REVISION")
    snapshot_download(
        repo_id="microsoft/deberta-v3-base",
        revision=tokenizer_revision,
        local_dir=str(args.output / "gliner"),
        allow_patterns=["config.json", "spm.model", "tokenizer_config.json"],
    )
    print("Downloaded microsoft/deberta-v3-base tokenizer into the GLiNER model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
