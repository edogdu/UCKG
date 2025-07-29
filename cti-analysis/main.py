import json
import subprocess
from docling.document_converter import DocumentConverter
from collections import defaultdict
from langchain_community.llms import Ollama
import spacy    
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

def ensure_mistral_model(model_name="mistral"):
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        if model_name not in result.stdout:
            print(f"Model '{model_name}' not found. Downloading...")
            subprocess.run(["ollama", "pull", model_name], check=True)
            print(f"Model '{model_name}' downloaded.")
        else:
            print(f"Model '{model_name}' already available.")
    except subprocess.CalledProcessError as e:
        print("Error checking or downloading model:", e)

class CyberTripleExtractor:
    def __init__(self, file_path, model_name="mistral"):
        self.file_path = file_path
        self.converter = DocumentConverter()
        self.llm = Ollama(model=model_name)
        
        
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

    def generate_prompt(self, text):
        object_types = ", ".join(self.malont_classes)
        predicates = ", ".join(self.malont_predicates)
        return f"""
You are a cybersecurity analyst.

From the text below, extract cybersecurity-relevant knowledge as subject-predicate-object triples.
Only extract triples that meet ALL of the following:
- The predicate is one of the following relationships: {predicates}
- The object corresponds to one of the following entity types: {object_types}
- The triple is clearly stated in the sentence (not inferred)
- Do not return duplicate or vague triples
- Limit to one triple per sentence

Output as a JSON array:
[
  {{
    "subject": "...",
    "predicate": "...",
    "object": "..."
  }}
]

If no valid triples are found, return:
"No related entities and relations."

Do not add any explanation. Just return valid JSON.

Analyze this text:
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
        print("Loading and converting document...")
        result = self.converter.convert(self.file_path)
        doc = result.document

        page_chunks = self.chunk_by_page(doc)
        chunk_results = []

        print("Extracting triples sentence-by-sentence...")
        for page_no, chunk_text in page_chunks:
            doc = nlp(chunk_text)
            sentences = [sent.text for sent in doc.sents]
            

            for i, sentence in enumerate(sentences):
                if len(sentence.strip()) < 40:
                    continue  # skip short or uninformative lines
                if not (self.rule_based_filter(sentence) or self.is_relevant_with_ner(sentence)):
                    continue

                try:
                    prompt = self.generate_prompt(sentence)
                    print(f"\n--- Page {page_no} | Sentence {i} ---")
                    print("Prompt sent to LLM:")
                    

                    response = self.llm.invoke(prompt)
                    print("Raw LLM response:")
                    print(response)
                    triples = json.loads(response)
                    chunk_results.append((sentence, page_no, i, triples))
                    for t in triples:
                        if not all(isinstance(t.get(k), str) for k in ("subject", "predicate", "object")):
                            print(f" Skipping invalid triple (non-string values): {t}")
                            continue

                        if self._is_valid_triple(t):
                            print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
                            self.valid_triples.append(t)
                        else:
                            print(f"Suspicious triple: {t}")
                    
                except Exception as e:
                    print(f"LLM error on page {page_no} sentence {i}: {e}")
        return chunk_results

    def build_dict(self, chunk_results):
        self.chunk_data = []
        for sentence, page_no, i, triples in chunk_results:
            self.chunk_data.append({
                "context": sentence,
                "technique": None,
                "triple": triples,
                "metadata": {
                    "page_number": page_no,
                    "id": str(i).zfill(3),  # pad with zeros like "001", "002"
                    "source": "TEXT",
                    "tactic_name": [],
                    "tactic": [],
                    "technique_name": None,
                    "sub_technique_name": None,
                    "sub_technique": None,
                    "description": None,
                    "tool_name": [],
                    "tool": [],
                    "note": None,
                    "link": None
                }
            })
        return self.chunk_data

    def save_to_json(self, output_path="chunk_data.json"):
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.chunk_data, f, indent=2, ensure_ascii=False)
            print("File saved successfully.")
        except Exception as e:
            print(f"Failed to save JSON: {e}")

    def _is_valid_triple(self, triple):
        return (
             any(cls.lower() in triple.get("subject", "").lower() for cls in self.malont_classes)
        )

if __name__ == "__main__":
    ensure_mistral_model("mistral")
    extractor = CyberTripleExtractor("cti-analysis/Extraction-master/Extraction-master/AnalysisOfCyberattackOnUS-3.pdf")
    raw_chunk_results = extractor.run()
    extractor.build_dict(raw_chunk_results)
    extractor.save_to_json("chunk_data.json")