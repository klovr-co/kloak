"""LangChain integration — DocumentTransformer + LangSmith trace masking + agent middleware."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from copy import deepcopy
from typing import Any

try:
    from langchain_core.documents import Document
    from langchain_core.documents.transformers import BaseDocumentTransformer
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
except ImportError as exc:
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it with: pip install kloak[langchain]"
    ) from exc

try:
    from langchain.agents.middleware import AgentMiddleware as _AgentMiddlewareBase

    _HAS_LANGCHAIN_AGENTS = True
except ImportError:
    _AgentMiddlewareBase = object  # type: ignore[misc,assignment]
    _HAS_LANGCHAIN_AGENTS = False

from kloak.config import DEFAULT_LANGUAGE, DEFAULT_SCORE_THRESHOLD
from kloak.engine import KloakEngine


class KloakAnonymizer(BaseDocumentTransformer):
    """Document transformer that redacts PII using kloak.

    Drop-in replacement for langchain_experimental's PresidioAnonymizer.
    Auto-detects installed kloak extras (malaysian, gitleaks, nlp).

    Args:
        mode: Redaction mode. Only ``"redact"`` is supported currently.
        language: Language code for analysis.
        score_threshold: Minimum confidence score to redact an entity.
        include: Entity types to redact (allowlist). Mutually exclusive priority over exclude.
        exclude: Entity types to skip (blocklist).
    """

    def __init__(
        self,
        *,
        mode: str = "redact",
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        if mode != "redact":
            raise ValueError(f"Unsupported mode: {mode!r}. Only 'redact' is currently supported.")
        self._mode = mode
        self._engine = KloakEngine(language=language, score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude

    def transform_documents(
        self, documents: Sequence[Document], **kwargs: Any
    ) -> Sequence[Document]:
        """Redact PII from document contents. Metadata is preserved."""
        result = []
        for doc in documents:
            redacted = self._engine.redact(
                doc.page_content, include=self._include, exclude=self._exclude
            )
            result.append(Document(page_content=redacted.text, metadata=deepcopy(doc.metadata)))
        return result


class KloakLangSmith:
    """LangSmith-compatible anonymizer for trace masking.

    Usage::

        from langsmith import Client
        client = Client(anonymizer=KloakLangSmith())

    Also works with the older API::

        client = Client(hide_inputs=KloakLangSmith(), hide_outputs=KloakLangSmith())

    Args:
        language: Language code for analysis.
        score_threshold: Minimum confidence score to redact an entity.
        include: Entity types to redact (allowlist).
        exclude: Entity types to skip (blocklist).
        max_depth: Optional recursion limit when walking nested structures.
            ``None`` (default) means no explicit depth limit.
    """

    def __init__(
        self,
        *,
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_depth: int | None = None,
    ) -> None:
        self._engine = KloakEngine(language=language, score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude
        self._max_depth = max_depth

    def __call__(self, data: Any) -> Any:
        """Walk a LangSmith data dict and redact string content."""
        return self._walk(data, depth=self._max_depth, seen=set())

    def _redact_text(self, text: str) -> str:
        if not text or not text.strip():
            return text
        return self._engine.redact(text, include=self._include, exclude=self._exclude).text

    def _walk(self, data: Any, *, depth: int | None, seen: set[int]) -> Any:
        if isinstance(data, str):
            return self._redact_text(data)
        if depth is not None and depth <= 0:
            return data
        if isinstance(data, dict):
            obj_id = id(data)
            if obj_id in seen:
                return data
            seen.add(obj_id)
            try:
                next_depth = None if depth is None else depth - 1
                return {k: self._walk(v, depth=next_depth, seen=seen) for k, v in data.items()}
            finally:
                seen.remove(obj_id)
        if isinstance(data, list):
            obj_id = id(data)
            if obj_id in seen:
                return data
            seen.add(obj_id)
            try:
                next_depth = None if depth is None else depth - 1
                return [self._walk(item, depth=next_depth, seen=seen) for item in data]
            finally:
                seen.remove(obj_id)
        return data


class KloakMiddleware(_AgentMiddlewareBase):
    """LangChain agent middleware that redacts PII from messages and tool outputs.

    Hooks into the agent runtime to redact PII before messages reach the LLM and
    after tools return results. Compatible with ``create_agent`` and Deep Agents'
    ``create_deep_agent``.

    Usage::

        from langchain.agents import create_agent
        from kloak.integrations.langchain import KloakMiddleware

        middleware = KloakMiddleware()
        agent = create_agent(model="...", middleware=[middleware])

    In tokenize mode, the mapping accumulated across the agent run is accessible via
    ``middleware.mapping`` and can be used to deanonymize the final output::

        result = agent.invoke(...)
        from kloak.engine import KloakEngine
        original = KloakEngine.deanonymize(result["output"], middleware.mapping)

    Args:
        mode: ``"redact"`` (irreversible) or ``"tokenize"`` (reversible with mapping).
        language: Language code for analysis.
        score_threshold: Minimum confidence score to redact an entity.
        include: Entity types to redact (allowlist). Takes priority over exclude.
        exclude: Entity types to skip (blocklist).
        redact_outputs: If ``True``, also redact LLM output via ``after_model``.
        tool_include: Only redact output from these tool names (allowlist).
            Takes priority over ``tool_exclude``. If neither is set, all tools
            are redacted.
        tool_exclude: Skip redaction for output from these tool names (blocklist).

    Note:
        ``KloakMiddleware`` instances should not be shared across concurrent agent
        runs — the ``mapping`` dict is not thread-safe.
    """

    def __init__(
        self,
        *,
        mode: str = "redact",
        language: str = DEFAULT_LANGUAGE,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        redact_outputs: bool = False,
        tool_include: list[str] | None = None,
        tool_exclude: list[str] | None = None,
    ) -> None:
        if not _HAS_LANGCHAIN_AGENTS:
            raise ImportError(
                "langchain (full package) is required for KloakMiddleware. "
                "Install it with: pip install kloak[langchain]"
            )
        if mode not in ("redact", "tokenize"):
            raise ValueError(f"Unsupported mode: {mode!r}. Use 'redact' or 'tokenize'.")
        self._mode = mode
        self._engine = KloakEngine(language=language, score_threshold=score_threshold)
        self._include = include
        self._exclude = exclude
        self._redact_outputs = redact_outputs
        self._tool_include = tool_include
        self._tool_exclude = tool_exclude
        self._mapping: dict[str, str] = {}

    @property
    def mapping(self) -> dict[str, str]:
        """Accumulated token→original mapping (only populated in tokenize mode)."""
        return dict(self._mapping)

    def reset_mapping(self) -> None:
        """Clear the accumulated mapping. Call between agent runs in tokenize mode."""
        self._mapping.clear()

    # -- AgentMiddleware hooks -------------------------------------------------

    def before_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Redact PII in the latest user message before it reaches the LLM."""
        messages = state["messages"]
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if isinstance(msg, HumanMessage):
                new_content = self._process_value(msg.content)
                if new_content != msg.content:
                    updated = HumanMessage(content=new_content, id=msg.id, name=msg.name)
                    new_messages = list(messages)
                    new_messages[i] = updated
                    return {"messages": new_messages}
                break
        return None

    def after_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Redact PII in LLM output when ``redact_outputs=True``."""
        if not self._redact_outputs:
            return None
        messages = state["messages"]
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if isinstance(msg, AIMessage):
                new_content = self._process_value(msg.content)
                if new_content != msg.content:
                    updated = AIMessage(content=new_content, id=msg.id)
                    new_messages = list(messages)
                    new_messages[i] = updated
                    return {"messages": new_messages}
                break
        return None

    def wrap_tool_call(self, request: Any, handler: Callable[..., Any]) -> Any:
        """Execute the tool and redact PII from its output (sync)."""
        result = handler(request)
        tool_name: str = request.tool_call.get("name", "")
        if self._should_redact_tool(tool_name):
            result = self._redact_tool_result(result)
        return result

    async def awrap_tool_call(self, request: Any, handler: Callable[..., Any]) -> Any:
        """Execute the tool and redact PII from its output (async)."""
        if asyncio.iscoroutinefunction(handler):
            result = await handler(request)
        else:
            result = handler(request)
        tool_name: str = request.tool_call.get("name", "")
        if self._should_redact_tool(tool_name):
            result = self._redact_tool_result(result)
        return result

    # -- Internal helpers ------------------------------------------------------

    def _process_text(self, text: str) -> str:
        """Redact or tokenize a string, accumulating mapping in tokenize mode."""
        if not text or not text.strip():
            return text
        if self._mode == "tokenize":
            result = self._engine.tokenize(text, include=self._include, exclude=self._exclude)
            self._mapping.update(result.mapping)
            return result.text
        return self._engine.redact(text, include=self._include, exclude=self._exclude).text

    def _process_value(self, value: Any, *, seen: set[int] | None = None) -> Any:
        """Recursively walk dicts/lists/strings and redact PII."""
        if seen is None:
            seen = set()
        if isinstance(value, str):
            return self._process_text(value)
        if isinstance(value, dict):
            obj_id = id(value)
            if obj_id in seen:
                return value
            seen.add(obj_id)
            try:
                return {k: self._process_value(v, seen=seen) for k, v in value.items()}
            finally:
                seen.discard(obj_id)
        if isinstance(value, list):
            obj_id = id(value)
            if obj_id in seen:
                return value
            seen.add(obj_id)
            try:
                return [self._process_value(item, seen=seen) for item in value]
            finally:
                seen.discard(obj_id)
        return value

    def _should_redact_tool(self, tool_name: str) -> bool:
        """Return True if this tool's output should be redacted."""
        if self._tool_include is not None:
            return tool_name in self._tool_include
        if self._tool_exclude is not None:
            return tool_name not in self._tool_exclude
        return True

    def _redact_tool_result(self, result: Any) -> Any:
        """Redact PII in a ToolMessage content (str or list)."""
        if not isinstance(result, ToolMessage):
            return result
        new_content = self._process_value(result.content)
        if new_content == result.content:
            return result
        return ToolMessage(
            content=new_content,
            tool_call_id=result.tool_call_id,
            name=result.name,
        )
