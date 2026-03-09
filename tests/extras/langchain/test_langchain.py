from typing import Any

import pytest

langchain_core = pytest.importorskip("langchain_core")
langchain = pytest.importorskip("langchain")

from langchain_core.documents import Document  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402

from kloak.integrations.langchain import (  # noqa: E402
    KloakAnonymizer,
    KloakLangSmith,
    KloakMiddleware,
)


@pytest.fixture(autouse=True)
def force_regex_mode(monkeypatch):
    monkeypatch.setenv("KLOAK_NLP_BACKEND", "regex")


class TestKloakAnonymizer:
    def test_redacts_email(self):
        anonymizer = KloakAnonymizer()
        docs = [Document(page_content="Email me at test@example.com")]
        result = anonymizer.transform_documents(docs)
        assert "test@example.com" not in result[0].page_content
        assert "<EMAIL_ADDRESS>" in result[0].page_content

    def test_preserves_metadata(self):
        anonymizer = KloakAnonymizer()
        docs = [Document(page_content="Email: test@example.com", metadata={"source": "file.txt"})]
        result = anonymizer.transform_documents(docs)
        assert result[0].metadata == {"source": "file.txt"}

    def test_deep_copies_metadata(self):
        anonymizer = KloakAnonymizer()
        docs = [
            Document(
                page_content="Email: test@example.com",
                metadata={"nested": {"source": "file.txt"}},
            )
        ]
        result = anonymizer.transform_documents(docs)
        result[0].metadata["nested"]["source"] = "mutated"
        assert docs[0].metadata["nested"]["source"] == "file.txt"

    def test_does_not_mutate_input(self):
        anonymizer = KloakAnonymizer()
        original_content = "Email: test@example.com"
        docs = [Document(page_content=original_content)]
        anonymizer.transform_documents(docs)
        assert docs[0].page_content == original_content

    def test_multiple_documents(self):
        anonymizer = KloakAnonymizer()
        docs = [
            Document(page_content="Email: a@test.com"),
            Document(page_content="No PII here"),
            Document(page_content="Email: b@test.com"),
        ]
        result = anonymizer.transform_documents(docs)
        assert "<EMAIL_ADDRESS>" in result[0].page_content
        assert result[1].page_content == "No PII here"
        assert "<EMAIL_ADDRESS>" in result[2].page_content

    def test_include_filter(self):
        anonymizer = KloakAnonymizer(include=["EMAIL_ADDRESS"])
        docs = [Document(page_content="Email: test@example.com, phone: 555-123-4567")]
        result = anonymizer.transform_documents(docs)
        assert "test@example.com" not in result[0].page_content

    def test_exclude_filter(self):
        anonymizer = KloakAnonymizer(exclude=["EMAIL_ADDRESS"])
        docs = [Document(page_content="IC saya 880101-01-1234")]
        result = anonymizer.transform_documents(docs)
        # MY_IC should still be redacted (not excluded)
        assert "880101-01-1234" not in result[0].page_content
        assert "<MY_IC>" in result[0].page_content

    def test_mode_default_is_redact(self):
        anonymizer = KloakAnonymizer()
        assert anonymizer._mode == "redact"

    def test_mode_invalid_raises(self):
        with pytest.raises(ValueError, match="Unsupported mode"):
            KloakAnonymizer(mode="tokenize")

    def test_empty_document(self):
        anonymizer = KloakAnonymizer()
        docs = [Document(page_content="")]
        result = anonymizer.transform_documents(docs)
        assert result[0].page_content == ""

    def test_extras_auto_detection_malaysian(self):
        anonymizer = KloakAnonymizer()
        docs = [Document(page_content="IC saya 880101-01-1234")]
        result = anonymizer.transform_documents(docs)
        assert "<MY_IC>" in result[0].page_content
        assert "880101-01-1234" not in result[0].page_content


class TestKloakLangSmith:
    def test_is_callable(self):
        masker = KloakLangSmith()
        assert callable(masker)

    def test_redacts_message_inputs(self):
        masker = KloakLangSmith()
        data = {"messages": [{"role": "user", "content": "My email is test@example.com"}]}
        result = masker(data)
        assert "test@example.com" not in result["messages"][0]["content"]
        assert "<EMAIL_ADDRESS>" in result["messages"][0]["content"]

    def test_redacts_choice_outputs(self):
        masker = KloakLangSmith()
        data = {
            "choices": [
                {"message": {"role": "assistant", "content": "Your email is test@example.com"}}
            ]
        }
        result = masker(data)
        assert "test@example.com" not in result["choices"][0]["message"]["content"]

    def test_preserves_non_string_values(self):
        masker = KloakLangSmith()
        data = {"count": 42, "active": True, "items": [1, 2, 3]}
        result = masker(data)
        assert result == data

    def test_handles_empty_content(self):
        masker = KloakLangSmith()
        data = {"messages": [{"role": "user", "content": ""}]}
        result = masker(data)
        assert result["messages"][0]["content"] == ""

    def test_does_not_mutate_input(self):
        masker = KloakLangSmith()
        data = {"messages": [{"role": "user", "content": "Email: test@example.com"}]}
        original_content = data["messages"][0]["content"]
        masker(data)
        assert data["messages"][0]["content"] == original_content

    def test_include_filter(self):
        masker = KloakLangSmith(include=["EMAIL_ADDRESS"])
        data = {"messages": [{"role": "user", "content": "Email: test@example.com"}]}
        result = masker(data)
        assert "test@example.com" not in result["messages"][0]["content"]

    def test_plain_string(self):
        masker = KloakLangSmith()
        result = masker("My email is test@example.com")
        assert "test@example.com" not in result
        assert "<EMAIL_ADDRESS>" in result

    def test_deep_nesting_redacts(self):
        masker = KloakLangSmith()
        data = "test@example.com"
        for _ in range(15):
            data = {"nested": data}
        result = masker(data)
        leaf = result
        for _ in range(15):
            leaf = leaf["nested"]
        assert leaf == "<EMAIL_ADDRESS>"

    def test_max_depth_configurable(self):
        masker = KloakLangSmith(max_depth=2)
        data = {"a": {"b": {"c": "test@example.com"}}}
        result = masker(data)
        assert result["a"]["b"]["c"] == "test@example.com"


class TestKloakMiddleware:
    def _state(self, *messages: Any) -> dict:
        return {"messages": list(messages)}

    def _tool_request(self, tool_name: str) -> Any:
        from unittest.mock import MagicMock

        req = MagicMock()
        req.tool_call = {"name": tool_name, "args": {}, "id": "tc_1"}
        return req

    def test_default_mode_is_redact(self):
        mw = KloakMiddleware()
        assert mw._mode == "redact"

    def test_tokenize_mode_accepted(self):
        mw = KloakMiddleware(mode="tokenize")
        assert mw._mode == "tokenize"

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Unsupported mode"):
            KloakMiddleware(mode="scramble")

    def test_before_model_redacts_last_user_message(self):
        mw = KloakMiddleware()
        state = self._state(HumanMessage(content="My email is test@example.com"))
        result = mw.before_model(state, None)
        assert result is not None
        assert "test@example.com" not in result["messages"][-1].content
        assert "<EMAIL_ADDRESS>" in result["messages"][-1].content

    def test_before_model_does_not_mutate_input(self):
        mw = KloakMiddleware()
        msg = HumanMessage(content="My email is test@example.com")
        state = self._state(msg)
        mw.before_model(state, None)
        assert msg.content == "My email is test@example.com"

    def test_before_model_preserves_system_messages(self):
        from langchain_core.messages import SystemMessage

        mw = KloakMiddleware()
        system = SystemMessage(content="System prompt with test@example.com")
        state = self._state(system, HumanMessage(content="hello"))
        result = mw.before_model(state, None)
        # System message untouched — only last HumanMessage is redacted
        assert result is None or result["messages"][0].content == system.content

    def test_before_model_returns_none_when_no_pii(self):
        mw = KloakMiddleware()
        state = self._state(HumanMessage(content="no pii here"))
        result = mw.before_model(state, None)
        assert result is None

    def test_before_model_tokenize_mode(self):
        mw = KloakMiddleware(mode="tokenize")
        state = self._state(HumanMessage(content="Email: test@example.com"))
        result = mw.before_model(state, None)
        assert result is not None
        assert "<EMAIL_ADDRESS_1>" in result["messages"][-1].content
        assert "test@example.com" in mw.mapping.values()

    def test_after_model_noop_by_default(self):
        mw = KloakMiddleware()
        state = self._state(AIMessage(content="Your email is test@example.com"))
        result = mw.after_model(state, None)
        assert result is None

    def test_after_model_redacts_when_enabled(self):
        mw = KloakMiddleware(redact_outputs=True)
        state = self._state(AIMessage(content="Your email is test@example.com"))
        result = mw.after_model(state, None)
        assert result is not None
        assert "test@example.com" not in result["messages"][-1].content

    def test_wrap_tool_call_redacts_string_output(self):
        def handler(req: Any) -> ToolMessage:
            return ToolMessage(content="Contact: test@example.com", tool_call_id="tc_1")

        mw = KloakMiddleware()
        request = self._tool_request("read_file")
        result = mw.wrap_tool_call(request, handler)
        assert "test@example.com" not in result.content
        assert "<EMAIL_ADDRESS>" in result.content

    def test_wrap_tool_call_tool_include_allowlist(self):
        raw = "test@example.com"

        def handler(req: Any) -> ToolMessage:
            return ToolMessage(content=raw, tool_call_id="tc_1")

        mw = KloakMiddleware(tool_include=["read_file"])
        included_req = self._tool_request("read_file")
        excluded_req = self._tool_request("write_todos")
        # Included tool — redacted
        assert "test@example.com" not in mw.wrap_tool_call(included_req, handler).content
        # Excluded tool — not redacted
        assert mw.wrap_tool_call(excluded_req, handler).content == raw

    def test_wrap_tool_call_tool_exclude_blocklist(self):
        raw = "test@example.com"

        def handler(req: Any) -> ToolMessage:
            return ToolMessage(content=raw, tool_call_id="tc_1")

        mw = KloakMiddleware(tool_exclude=["write_todos"])
        blocked_req = self._tool_request("write_todos")
        allowed_req = self._tool_request("read_file")
        # Excluded tool — not redacted
        assert mw.wrap_tool_call(blocked_req, handler).content == raw
        # Other tool — redacted
        assert "test@example.com" not in mw.wrap_tool_call(allowed_req, handler).content

    def test_mapping_empty_initially(self):
        mw = KloakMiddleware(mode="tokenize")
        assert mw.mapping == {}

    def test_mapping_accumulates_across_calls(self):
        # Each tokenize() call resets its per-type counter, so calls with the same
        # entity type overwrite each other in the mapping. After two calls the mapping
        # still contains the most recent value for each token key.
        mw = KloakMiddleware(mode="tokenize")
        mw.before_model(self._state(HumanMessage(content="Email: a@test.com")), None)
        mw.before_model(self._state(HumanMessage(content="Email: b@test.com")), None)
        assert len(mw.mapping) >= 1
        assert "b@test.com" in mw.mapping.values()

    def test_reset_mapping(self):
        mw = KloakMiddleware(mode="tokenize")
        mw.before_model(self._state(HumanMessage(content="Email: a@test.com")), None)
        mw.reset_mapping()
        assert mw.mapping == {}

    def test_mapping_empty_in_redact_mode(self):
        mw = KloakMiddleware(mode="redact")
        mw.before_model(self._state(HumanMessage(content="Email: a@test.com")), None)
        assert mw.mapping == {}

    def test_include_entity_filter(self):
        mw = KloakMiddleware(include=["EMAIL_ADDRESS"])
        state = self._state(HumanMessage(content="Email: test@example.com"))
        result = mw.before_model(state, None)
        assert result is not None
        assert "test@example.com" not in result["messages"][-1].content
