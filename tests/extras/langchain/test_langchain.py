import pytest

langchain_core = pytest.importorskip("langchain_core")

from langchain_core.documents import Document  # noqa: E402

from kloak.integrations.langchain import KloakAnonymizer, KloakLangSmith  # noqa: E402


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
