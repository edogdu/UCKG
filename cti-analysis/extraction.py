import json
import os
import requests
import subprocess
from docling.document_converter import DocumentConverter
from collections import defaultdict
from langchain_community.llms import Ollama
import spacy   
import re

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    from spacy.cli import download
    download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")
from spacy.matcher import PhraseMatcher
nlp = spacy.load("en_core_web_sm")
if "sentencizer" not in nlp.pipe_names:
    nlp.add_pipe("sentencizer")
matcher = PhraseMatcher(nlp.vocab, attr = "LOWER")

def ensure_ollama_model(model_name="mistral", base_url="http://localhost:11434"):
    try:
        # Check if the model is available
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
            stop=["</think>", "<think>"]
        )
        self.suspicious_triples = 0
        self.malont_classes = [
            'Staging', 'Adware', 'CommandAndControl', 'Spyware', 'DDoS', 'DomainName', 'Dropper', 'Port', 'MD5',
            'Protocol', 'VirusScanner', 'Downloader', 'Ransomware', 'OperatingSystem', 'Rootkit',
            'AttackPattern_SmallDescription', 'IPAddress', 'Bootkit', 'Hardware', 'SSDeep',
            'Application', 'AttackPattern', 'Phishing', 'Campaign', 'SHA-256', 'System',
            'Vulnerability_Desc', 'Anonymization', 'Backdoor', 'Location', 'Organization',
            'Reconnaissance', 'Exploit-kit', 'Time', 'MalwareAnalysis', 'ResourceExploitation',
            'SHA', 'HostingMalware', 'SHA-1', 'Unknown', 'HostingTargetLists', 'Hash',
            'AttackPattern_LargeDescription', 'Software', 'Network', 'Indicator', 'Trojan', 'Botnet',
            'Worm', 'EmailAddress', 'Malware', 'RogueSecuritySoftware', 'vHash', 'Filepath', 'Region',
            'Report', 'Virus', 'ThreatActor', 'Keylogger', 'Browser', 'ScreenCapture',
            'Vulnerability_CVEID', 'URL', 'Wiper', 'Filename', 'Infrastructure', 'MalwareFamily',
            'Person', 'Webshell', 'Vulnerability', 'Bot', 'RemoteAccessTrojan-RAT', 'Country',
            'Exfiltration', 'Amplification'
        ]
        self.patterns = [nlp.make_doc(term) for term in self.malont_classes]
        matcher.add("MALONT", self.patterns)
        
        
        self.malont_predicates = [
            "targets", "communicatesWith", "uses", "has", "hasAlias",
            "hasVulnerability", "indicates", "exploits", "hasAuthor", "belongsTo"
        ]
        
        
        self.valid_triples = []
        self.chunk_data = []
        self.sentences_total = 0
        self.sentences_used = 0
        self.raw_triples = 0
        self.rejection_stats = {
            "bad_structure": 0,
            "invalid_class_or_predicate": 0
        }
        self.pages_parsed = 0
        self.runtime_seconds = 0

    def generate_prompt(self, text,):
        entity_types = ", ".join(self.malont_classes)
        predicates = ", ".join(self.malont_predicates)
        return f"""
You are a cybersecurity analyst extracting structured intelligence.

TASK:
From the sentence below, extract at most 5 subject–predicate–object triples.

RULES:
1. Subject.type and Object.type MUST be in: [{entity_types}]
2. Predicate MUST be in: [{predicates}]
3. Use ONLY explicit relationships stated in the text (no guesses).
4. Return "NO_TRIPLES" if no valid relationships exist.
5. All names must be strings exactly as they appear in the sentence (no paraphrasing).
6. Each triple must include a direct quote from the sentence that supports it.

OUTPUT FORMAT (JSON array only, no text outside the array):
[
  {{
    "subject": {{"name": "<string>", "type": "<type-from-list>"}},
    "predicate": "<predicate-from-list>",
    "object": {{"name": "<string>", "type": "<type-from-list>"}},
    "evidence": {{
      "quote": "<exact substring from sentence>",
    }}
  }}
]

Sentence:
\"\"\"{text}\"\"\"
"""


    def is_relevant_with_ner(self, sentence):
        doc = nlp(sentence)
        entity_labels = {ent.label_ for ent in doc.ents}
        return bool(entity_labels & {"ORG", "PRODUCT", "GPE", "DATE"})
    
    def rule_based_filter(self, sentence):
        doc = nlp(sentence)
        matches = matcher(doc)
        return len(matches) > 0
    
   
    
    def chunk_by_page(self, doc):
        page_chunks = defaultdict(str)
        for text_item in doc.texts:
            if not text_item.prov:
                continue 
            if hasattr(text_item, "content_layer") and text_item.content_layer != "body":
                continue
            try:
                page_no = text_item.prov[0].page_no
                page_chunks[page_no] += " " + text_item.text.strip()
            except Exception:
                continue

        return sorted(page_chunks.items())


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
            doc = nlp(chunk_text)
            sentences = [sent.text for sent in doc.sents]

            for i, sentence in enumerate(sentences):
                self.sentences_total += 1
                if len(sentence.strip()) < 40:
                    continue  # skip short or uninformative lines
                if not (self.rule_based_filter(sentence) or self.is_relevant_with_ner(sentence)):
                    continue
                self.sentences_used += 1

                try:
                    prompt = self.generate_prompt(sentence)
                    print(f"\n--- Page {page_no} | Sentence {i} ---")
                    print("Prompt sent to LLM:")

                    response = self.llm.invoke(prompt)
                    print("Raw LLM response:")
                    print(response)
                    triples = json.loads(response)
                    # Normalize to a list of triples
                    if isinstance(triples, dict):
                        triples = [triples]
                    elif isinstance(triples, str):
                        # Treat string outputs like "NO_TRIPLES" as no results
                        triples_upper = triples.strip().upper()
                        if triples_upper in {"NO_TRIPLES", "NO RELATED ENTITIES AND RELATIONS.", "NONE"}:
                            triples = []
                        else:
                            # Unexpected string payload; ignore safely
                            triples = []
                    elif not isinstance(triples, list):
                        # Any other JSON type -> ignore
                        triples = []
                    self.raw_triples += len(triples)
                    chunk_results.append((sentence, page_no, i, triples))
                    for t in triples:
                        if self._is_valid_triple(t):
                            print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
                            self.valid_triples.append(t)
                        else:
                            print(f"Suspicious triple: {t}")
                            self.suspicious_triples += 1
                            # Determine rejection reason
                            s = t.get("subject", {})
                            o = t.get("object", {})
                            p = t.get("predicate", "")
                            if not (isinstance(p, str) and p.strip() in self.malont_predicates):
                                self.rejection_stats["invalid_class_or_predicate"] += 1
                            elif s.get("type", "") not in self.malont_classes or o.get("type", "") not in self.malont_classes:
                                self.rejection_stats["invalid_class_or_predicate"] += 1
                            else:
                                self.rejection_stats["bad_structure"] += 1

                except Exception as e:
                    print(f"LLM error on page {page_no} sentence {i}: {e}")
        self.runtime_seconds = time.time() - start_time
        return chunk_results

    def build_dict(self, chunk_results):
        """Build chunk_data using only valid triples (suspicious ones are excluded)."""
        self.chunk_data = []
        for sentence, page_no, i, triples in chunk_results:
            # Filter to valid triples only
            valid_only = [t for t in triples if self._is_valid_triple(t)]
            if not valid_only:
                continue  # skip sentences with no valid triples
            self.chunk_data.append({
                "context": sentence,
                "triple": valid_only,
                "metadata": {
                    "page_number": page_no,
                    "id": str(i).zfill(3),
                    "source": "TEXT"
                }
            })
        return self.chunk_data
    
    def safe_filename(self, name: str) -> str:
   
        return re.sub(r'[<>:"/\\|?*]', '_', name)
     
    def save_to_json(self, output_filename="chunk_data.json"):
        try:
            input_dir = os.path.dirname(self.file_path)
            output_dir = os.path.join(input_dir, "extracted_triples")
            os.makedirs(output_dir, exist_ok=True)

            output_filename = self.safe_filename(output_filename)
            output_path = os.path.join(output_dir, output_filename)

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

    def _is_valid_triple(self, triple):
        s = triple.get("subject", {})
        o = triple.get("object", {})
        p = triple.get("predicate", "")

        subject_type = s.get("type", "")
        object_type = o.get("type", "")

        return (
            isinstance(p, str) and p.strip() in self.malont_predicates and
            subject_type in self.malont_classes and
            object_type in self.malont_classes
        )

if __name__ == "__main__":
    models = [
        # "openhermes",
        # "mistral:7b",
        # "zephyr:7b",
        "qwen3:4b",
        # "phi3:3.8b",
        # "gemma2:9b"
    ]
    for model in models:
        extractor = CyberTripleExtractor("cti-analysis/AnalysisOfCyberattackOnUS.pdf", model, "http://localhost:11434")
        raw_chunk_results = extractor.run()
        extractor.build_dict(raw_chunk_results)
        out_name = extractor.safe_filename(f"chunk_data_{model}.json")
        extractor.save_to_json(out_name)