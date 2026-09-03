"""bedrock_provider.py - the fork's ONLY model egress path (fork ADR 0001 s2).

Every LLM and embedding call in this fork goes through here: AWS Bedrock, no
direct vendor API. That is the whole reason the fork exists, so the module is
deliberately small and refuses rather than improvises.

Configuration (all read at call time, never at import):
    OBSIDIAN_BEDROCK_MODEL_ID    generation / synthesis model (Sonnet tier)
    OBSIDIAN_BEDROCK_GUARD_MODEL_ID  the three OWASP guard checks (Haiku tier;
                                 falls back to OBSIDIAN_BEDROCK_MODEL_ID)
    OBSIDIAN_BEDROCK_EMBED_MODEL_ID  embeddings (Titan / Cohere on Bedrock)
    AWS_REGION                   Bedrock region
    OBSIDIAN_BEDROCK_MAX_TOKENS  per-call output cap (default 512)

Two hard-won constraints from the platform side, encoded here so this fork does
not rediscover them:

  * Model ids must be the SHORT form. A cross-region inference profile needs
    the profile id AND foundation-model IAM, and a long ARN in this field fails
    at invoke time with an unhelpful error.
  * The first InvokeModel against a new model auto-subscribes the account
    through Bedrock's marketplace flow. That is expected, not a fault - but it
    means a first call can fail once while the subscription settles.

Failure posture: `BedrockUnavailable` on any missing configuration, missing
boto3, or API error. Callers must treat that as a FAILURE, never as a pass -
`owasp_pipeline.check_llm_backed` is the reference behaviour.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

DEFAULT_MAX_TOKENS = 512
_ANTHROPIC_VERSION = "bedrock-2023-05-31"


class BedrockUnavailable(RuntimeError):
    """Bedrock could not be reached, or is not configured. Never a pass."""


def _client(service: str = "bedrock-runtime"):
    region = os.getenv("AWS_REGION", "").strip()
    if not region:
        raise BedrockUnavailable("AWS_REGION is not set")
    try:
        import boto3  # imported lazily: the fork must import without boto3
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise BedrockUnavailable("boto3 is not installed") from exc
    try:
        return boto3.client(service, region_name=region)
    except Exception as exc:  # noqa: BLE001 - credential chain, endpoint, etc.
        raise BedrockUnavailable(f"cannot construct {service} client: {exc}") from exc


def _require_model(env_var: str, fallback_env: Optional[str] = None) -> str:
    model = os.getenv(env_var, "").strip()
    if not model and fallback_env:
        model = os.getenv(fallback_env, "").strip()
    if not model:
        raise BedrockUnavailable(f"{env_var} is not set")
    if model.startswith("arn:"):
        # A long ARN here fails at invoke time with an opaque error; refuse
        # early and say which form is wanted.
        raise BedrockUnavailable(
            f"{env_var} must be a short model id or inference-profile id, not an ARN"
        )
    return model


def invoke_text(
    prompt: str,
    *,
    system: Optional[str] = None,
    guard_tier: bool = False,
    max_tokens: Optional[int] = None,
    client: Any = None,
) -> str:
    """One text completion. `guard_tier=True` selects the Haiku-tier model.

    `client` is injectable so tests exercise the request/response shaping
    without network access; production passes nothing.
    """
    model = (
        _require_model("OBSIDIAN_BEDROCK_GUARD_MODEL_ID", "OBSIDIAN_BEDROCK_MODEL_ID")
        if guard_tier
        else _require_model("OBSIDIAN_BEDROCK_MODEL_ID")
    )
    cap = int(max_tokens or os.getenv("OBSIDIAN_BEDROCK_MAX_TOKENS", DEFAULT_MAX_TOKENS))
    body: Dict[str, Any] = {
        "anthropic_version": _ANTHROPIC_VERSION,
        "max_tokens": cap,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    runtime = client or _client()
    try:
        resp = runtime.invoke_model(modelId=model, body=json.dumps(body))
        payload = resp["body"].read() if hasattr(resp.get("body"), "read") else resp["body"]
        data = json.loads(payload)
    except BedrockUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - any API/parse failure is unavailable
        raise BedrockUnavailable(f"invoke_model failed for {model}: {exc}") from exc

    content = data.get("content") or []
    for block in content:
        if isinstance(block, dict) and block.get("type", "text") == "text":
            return str(block.get("text", ""))
    raise BedrockUnavailable(f"no text block in response from {model}")


def embed(text: str, *, client: Any = None) -> List[float]:
    """One embedding vector via Bedrock. Replaces the local-only embed path."""
    model = _require_model("OBSIDIAN_BEDROCK_EMBED_MODEL_ID")
    runtime = client or _client()
    # Titan takes inputText; Cohere takes texts+input_type. Shape by model id
    # rather than adding a second config knob the caller has to keep in sync.
    if "cohere" in model:
        body = {"texts": [text], "input_type": "search_document"}
    else:
        body = {"inputText": text}
    try:
        resp = runtime.invoke_model(modelId=model, body=json.dumps(body))
        payload = resp["body"].read() if hasattr(resp.get("body"), "read") else resp["body"]
        data = json.loads(payload)
    except BedrockUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        raise BedrockUnavailable(f"embed failed for {model}: {exc}") from exc

    if isinstance(data.get("embedding"), list):
        return [float(x) for x in data["embedding"]]
    embeddings = data.get("embeddings")
    if isinstance(embeddings, list) and embeddings and isinstance(embeddings[0], list):
        return [float(x) for x in embeddings[0]]
    raise BedrockUnavailable(f"no embedding in response from {model}")


def available(*, embeddings: bool = False, guard: bool = False) -> bool:
    """Cheap configuration probe. Does NOT prove Bedrock is reachable.

    Used to decide whether a code path may run at all; a True here still means
    the call itself can raise BedrockUnavailable, which callers must treat as a
    failure.
    """
    try:
        if embeddings:
            _require_model("OBSIDIAN_BEDROCK_EMBED_MODEL_ID")
        elif guard:
            _require_model("OBSIDIAN_BEDROCK_GUARD_MODEL_ID", "OBSIDIAN_BEDROCK_MODEL_ID")
        else:
            _require_model("OBSIDIAN_BEDROCK_MODEL_ID")
    except BedrockUnavailable:
        return False
    return bool(os.getenv("AWS_REGION", "").strip())
