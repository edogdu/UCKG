import json
import os
import requests
from docling.document_converter import DocumentConverter
from collections import defaultdict
from langchain_community.llms import Ollama
import spacy
import re
from spacy.matcher import PhraseMatcher

# Ontology plumbing
from ontologies.base import validate_triple_semantics
from ontologies import connection 
from ontologies import malont 

# -------- spaCy setup --------
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    from spacy.cli import download
    download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

if "sentencizer" not in nlp.pipe_names:
    nlp.add_pipe("sentencizer")

matcher = PhraseMatcher(nlp.vocab, attr="LOWER")

# -------- feature flags --------
USE_CONTEXT_WINDOW = True
CONTEXT_WINDOW_K = 1  # prev/next sentence window size

def ensure_ollama_model(model_name="mistral", base_url="http://localhost:11434"):
    try:
        resp = requests.get(f"{base_url}/api/tags")
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        if model_name not in models:
            print(f"Model '{model_name}' not found. Downloading...")
            pull_resp = requests.post(f"{base_url}/api/pull", json={"name": model_name})
            pull_resp.raise_for_status()
            print(f"Model '{model_name}' downloaded.")
        else:
            print(f"Model '{model_name}' already available.")
    except Exception as e:
        print("Error checking or downloading model:", e)

class CyberTripleExtractor:
    def __init__(self, file_path, model_name="mistral", ollama_base_url="http://localhost:11434"):
        self.file_path = file_path
        self.ollama_base_url = ollama_base_url
        self.converter = DocumentConverter()
        self.model_name = model_name

        # Ensure the Ollama model is present before constructing the client
        ensure_ollama_model(model_name=self.model_name, base_url=self.ollama_base_url)
        self.llm = Ollama(
            model=model_name,
            base_url=self.ollama_base_url,
            num_ctx=2048,
            format="json",
            stop=["</think>", "<think>"],
        )

        self.ontology = malont.get_config()


        self.SUBJECT_TYPES        = self.ontology.SUBJECT_TYPES
        self.OBJECT_TYPES         = self.ontology.OBJECT_TYPES
        self.PREDICATES           = self.ontology.PREDICATES
        self.LITERAL_TYPES        = self.ontology.LITERAL_TYPES
        self.ATTRIBUTE_PREDICATES = self.ontology.ATTRIBUTE_PREDICATES
        self.RELATION_PREDICATES  = self.ontology.RELATION_PREDICATES

        # Optional: if you have a hierarchy map in the ontology
        self.PARENT_OF = getattr(self.ontology, "PARENT_OF", {})

       
        # Seed an ontology term matcher for cheap pre-screening
        patterns = [nlp.make_doc(t.split(":")[-1]) for t in sorted(self.ontology.SUBJECT_TYPES)]
        if patterns:
            matcher.add("ONTO", patterns)

        # IOC/TTP detectors (cheap + effective)
        self._ioc_patterns = {
            "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
            "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", re.I),
            "url": re.compile(r"\bhttps?://[^\s)>\]}]+", re.I),
            "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
            "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
            "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
            "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
            "port": re.compile(r"\bport\s*(?:\d{1,5})\b", re.I),
        }
        self._cti_keywords = {
            "rat","remote access trojan","botnet","c2","command and control","dropper",
            "exploit kit","webshell","keylogger","wiper","exfiltration","phishing",
            "ddos","rootkit","backdoor","loader","persistence","lateral movement"
        }

        # Metrics
        self.suspicious_triples = 0
        self.valid_triples = []
        self.chunk_data = []
        self.sentences_total = 0
        self.sentences_used = 0
        self.raw_triples = 0
        self.rejection_stats = {"bad_structure": 0, "invalid_class_or_predicate": 0}
        self.pages_parsed = 0
        self.runtime_seconds = 0

    # ---------- prompt with optional context window ----------
    def generate_prompt(self, text, ctx_before="", ctx_after=""):
        entity_types = ", ".join(sorted(self.SUBJECT_TYPES | self.OBJECT_TYPES))
        predicates = ", ".join(sorted(self.PREDICATES))
        return f"""
You are a cybersecurity analyst extracting structured intelligence.

TASK:
Extract at most 5 subject–predicate–object triples from the TARGET sentence only.

CONSTRAINTS:
1) Subject.type and Object.type MUST be in: [{entity_types}]
2) Predicate MUST be in: [{predicates}]
3) Use ONLY relationships explicitly stated in the TARGET sentence (no guessing).
4) You MAY use the CONTEXT (neighboring sentences) only to resolve references (e.g., pronouns, aliases).
5) Every triple MUST include an exact quote from the TARGET sentence as evidence.
6) If no valid triples exist in the TARGET sentence, return "NO_TRIPLES".

CONTEXT (optional, for disambiguation only):
BEFORE: {ctx_before}
AFTER: {ctx_after}

TARGET SENTENCE:
\"\"\"{text}\"\"\"

OUTPUT (JSON array only):
[
  {{
    "subject": {{"name": "<string>", "type": "<type-from-list>"}},
    "predicate": "<predicate-from-list>",
    "object": {{"name": "<string>", "type": "<type-from-list>"}},
    "evidence": {{"quote": "<exact substring from TARGET sentence>"}}
  }}
]
""".strip()

    # ---------- relevance gate ----------
    def _has_ioc_or_cti_terms(self, text: str) -> bool:
        s = text.lower()
        if any(k in s for k in self._cti_keywords):
            return True
        for rx in self._ioc_patterns.values():
            if rx.search(text):
                return True
        return False

    def is_relevant(self, sentence: str) -> bool:
        doc = nlp(sentence)
        entity_labels = {ent.label_ for ent in doc.ents}
        ner_hit  = bool(entity_labels & {"ORG", "PRODUCT", "GPE", "DATE"})
        onto_hit = len(matcher(doc)) > 0
        ioc_hit  = self._has_ioc_or_cti_terms(sentence)
        return ner_hit or onto_hit or ioc_hit

    def _neighbor_context(self, sentences, idx, k=1):
        left = sentences[max(0, idx - k): idx]
        right = sentences[idx + 1: idx + 1 + k]
        return " ".join(left).strip(), " ".join(right).strip()

    # ---------- conversion & chunking ----------
    def chunk_by_page(self, doc):
        page_chunks = defaultdict(str)
        for text_item in doc.texts:
            if not getattr(text_item, "prov", None):
                continue
            if hasattr(text_item, "content_layer") and text_item.content_layer != "body":
                continue
            try:
                page_no = text_item.prov[0].page_no
                page_chunks[page_no] += " " + text_item.text.strip()
            except Exception:
                continue
        return sorted(page_chunks.items())

    # ---------- main run ----------
    def run(self):
        import time
        start_time = time.time()
        print("Loading and converting document...")
        result = self.converter.convert(self.file_path)
        doc = result.document

        page_chunks = self.chunk_by_page(doc)
        chunk_results = []
        self.pages_parsed = len(page_chunks)

        print("Extracting triples sentence-by-sentence...")
        for page_no, chunk_text in page_chunks:
            doc_spacy = nlp(chunk_text)
            sentences = [sent.text for sent in doc_spacy.sents]

            for i, sentence in enumerate(sentences):
                self.sentences_total += 1
                if len(sentence.strip()) < 40:
                    continue
                if not self.is_relevant(sentence):
                    continue
                self.sentences_used += 1

                ctx_before, ctx_after = ("", "")
                if USE_CONTEXT_WINDOW:
                    ctx_before, ctx_after = self._neighbor_context(sentences, i, CONTEXT_WINDOW_K)

                try:
                    prompt = self.generate_prompt(sentence, ctx_before=ctx_before, ctx_after=ctx_after)
                    print(f"\n--- Page {page_no} | Sentence {i} ---")
                    print("Prompt sent to LLM:")
                    response = self.llm.invoke(prompt)
                    print("Raw LLM response:")
                    print(response)

                    triples = json.loads(response)
                    if isinstance(triples, dict):
                        triples = [triples]
                    elif isinstance(triples, str):
                        if triples.strip().upper() in {"NO_TRIPLES", "NO RELATED ENTITIES AND RELATIONS.", "NONE"}:
                            triples = []
                        else:
                            triples = []
                    elif not isinstance(triples, list):
                        triples = []

                    self.raw_triples += len(triples)
                    chunk_results.append((sentence, page_no, i, triples, ctx_before, ctx_after))

                    for t in triples:
                        if self._is_valid_triple(t):
                            print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
                            self.valid_triples.append(t)
                        else:
                            print(f"Suspicious triple: {t}")
                            self.suspicious_triples += 1
                            if not isinstance(t, dict):
                                self.rejection_stats["bad_structure"] += 1
                            elif not validate_triple_semantics(self.ontology, t):
                                self.rejection_stats["invalid_class_or_predicate"] += 1
                            else:
                                self.rejection_stats["bad_structure"] += 1

                except Exception as e:
                    print(f"LLM error on page {page_no} sentence {i}: {e}")

        self.runtime_seconds = time.time() - start_time
        return chunk_results

    def build_dict(self, chunk_results):
        self.chunk_data = []
        for sentence, page_no, i, triples, ctx_before, ctx_after in chunk_results:
            valid_only = [t for t in triples if self._is_valid_triple(t)]
            if not valid_only:
                continue
            self.chunk_data.append({
                "context": sentence,
                "triple": valid_only,
                "metadata": {
                    "page_number": page_no,
                    "id": str(i).zfill(3),
                    "source": "TEXT",
                    "context_before": ctx_before,
                    "context_after": ctx_after,
                    "window_k": CONTEXT_WINDOW_K if USE_CONTEXT_WINDOW else 0,
                }
            })
        return self.chunk_data

    def safe_filename(self, name: str) -> str:
        return re.sub(r'[<>:"/\\|?*]', '_', name)

    def save_to_json(self, output_filename="chunk_data.json", base_dir=None):
        try:
            if base_dir is not None:
                os.makedirs(base_dir, exist_ok=True)
                filename = self.safe_filename(os.path.basename(output_filename))
                output_path = os.path.join(base_dir, filename)
            elif os.path.isabs(output_filename) or os.path.dirname(output_filename):
                os.makedirs(os.path.dirname(output_filename), exist_ok=True)
                output_path = output_filename
            else:
                input_dir = os.path.dirname(self.file_path)
                output_dir = os.path.join(input_dir, "extracted_triples")
                os.makedirs(output_dir, exist_ok=True)
                filename = self.safe_filename(output_filename)
                output_path = os.path.join(output_dir, filename)

            metrics = {
                "file_name": os.path.basename(self.file_path),
                "model_used": self.model_name,
                "num_pages": self.pages_parsed,
                "num_sentences_total": self.sentences_total,
                "num_sentences_used": self.sentences_used,
                "num_raw_triples": self.raw_triples,
                "num_valid_triples": len(self.valid_triples),
                "num_suspicious_triples": self.suspicious_triples,
                "avg_triples_per_sentence": self.raw_triples / self.sentences_used if self.sentences_used else 0,
                "rejection_stats": self.rejection_stats,
                "runtime_seconds": self.runtime_seconds,
            }

            metadata = {"metrics": metrics, "data": self.chunk_data}

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            print(f"File saved successfully to: {output_path}")
        except Exception as e:
            print(f"Failed to save JSON: {e}")

    # -------- single source of truth: ontology validator --------
    def _is_valid_triple(self, triple):
        return validate_triple_semantics(self.ontology, triple)

if __name__ == "__main__":
    models = ["gemma2:9b"]
    for model in models:
        extractor = CyberTripleExtractor("cti-analysis/AnalysisOfCyberattackOnUS.pdf", model, "http://localhost:11434")
        raw_chunk_results = extractor.run()
        extractor.build_dict(raw_chunk_results)
        out_name = extractor.safe_filename(f"chunk_data_{model}.json")
        extractor.save_to_json(out_name)
