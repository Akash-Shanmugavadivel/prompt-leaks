"""Download the local semantic-repetition model."""

from pathlib import Path

from huggingface_hub import snapshot_download


def main() -> int:
    target = Path(__file__).resolve().parents[1] / "models" / "quality" / "all-MiniLM-L6-v2"
    snapshot_download(
        repo_id="sentence-transformers/all-MiniLM-L6-v2",
        local_dir=str(target),
        allow_patterns=[
            "1_Pooling/config.json",
            "config.json",
            "config_sentence_transformers.json",
            "model.safetensors",
            "modules.json",
            "sentence_bert_config.json",
            "special_tokens_map.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "vocab.txt",
        ],
    )
    print(f"Downloaded response-quality model to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
