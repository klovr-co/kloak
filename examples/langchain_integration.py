"""
LangChain integration — document anonymizer + LangSmith trace masking + agent middleware.

Install: pip install kloak[langchain]
"""

import logging

from langchain_core.documents import Document

from kloak.integrations.langchain import KloakAnonymizer, KloakLangSmith, KloakMiddleware

logging.getLogger("kloak").setLevel(logging.ERROR)


# --- Surface B: Document pipeline anonymizer --------------------------------

docs = [
    Document(
        page_content="Email ahmad@mail.com for details.",
        metadata={"source": "chat.txt"},
    ),
    Document(
        page_content="IC saya 880101-01-1234, call 012-3456789.",
        metadata={"source": "msg.txt"},
    ),
]

anonymizer = KloakAnonymizer()
redacted = anonymizer.transform_documents(docs)

for doc in redacted:
    print(f"[{doc.metadata['source']}] {doc.page_content}")
# → [chat.txt] Email <EMAIL_ADDRESS> for details.
# → [msg.txt] IC saya <MY_IC>, call <MY_MOBILE>.


# --- With entity filtering --------------------------------------------------

anonymizer = KloakAnonymizer(include=["EMAIL_ADDRESS"])
redacted = anonymizer.transform_documents(docs)
print(redacted[0].page_content)
# → Email <EMAIL_ADDRESS> for details.
print(redacted[1].page_content)
# → IC saya 880101-01-1234, call 012-3456789.  (only EMAIL_ADDRESS targeted)


# --- Surface A: LangSmith trace masking -------------------------------------

masker = KloakLangSmith()

# Simulates LangSmith input format
trace_input = {
    "messages": [{"role": "user", "content": "My name is Ahmad and my email is ahmad@mail.com"}]
}
redacted_input = masker(trace_input)
print(redacted_input["messages"][0]["content"])
# → My name is Ahmad and my email is <EMAIL_ADDRESS>

# Use with LangSmith Client:
# from langsmith import Client
# client = Client(anonymizer=KloakLangSmith())


# --- Surface C: Agent middleware (LangChain agents + Deep Agents) ------------

# Basic redaction — scrubs PII before LLM calls and from tool outputs
middleware = KloakMiddleware()
# agent = create_agent(model="anthropic:claude-sonnet-4-6", middleware=[middleware])
# agent = create_deep_agent(model="anthropic:claude-sonnet-4-6", middleware=[middleware])

# Tokenize mode — reversible redaction; recover originals after the agent run
# from kloak.engine import KloakEngine
tokenize_mw = KloakMiddleware(mode="tokenize")
# result = agent.invoke({"messages": [{"role": "user", "content": "..."}]})
# Restore PII in the final output using the accumulated mapping:
# original = KloakEngine.deanonymize(result["output"], tokenize_mw.mapping)

# Per-tool filtering — only redact output from file tools, not internal tools
filtered_mw = KloakMiddleware(
    tool_include=["read_file", "search_web"],
    redact_outputs=True,  # also redact LLM responses
)

# Example output — middleware operating on a simulated before_model state
from langchain_core.messages import HumanMessage  # noqa: E402

state = {"messages": [HumanMessage(content="My name is Ahmad and my email is ahmad@mail.com")]}
result = middleware.before_model(state, None)
if result:
    print(result["messages"][-1].content)
    # → My name is Ahmad and my email is <EMAIL_ADDRESS>
