import json
from docling.document_converter import DocumentConverter
from collections import defaultdict
from langchain_community.llms import Ollama
from nltk.tokenize import sent_tokenize
import spacy    
from spacy.matcher import PhraseMatcher
nlp = spacy.load("en_core_web_sm")
matcher = PhraseMatcher(nlp.vocab, attr = "LOWER")



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
        
        
        self.malont_objects = [
            "targets", "communicatesWith", "uses", "has", "hasAlias",
            "hasVulnerability", "indicates", "exploits", "hasAuthor", "belongsTo"
        ]
        
        
        self.prompt_template = f"""
           You are a cybersecurity analyst.

        From the text below, extract all cybersecurity-relevant knowledge in the form of subject-predicate-object triples.
        Only extract triples that meet ALL of the following:
        - Reference a known attacker, malware, tool, vulnerability, or MITRE technique
        - Are clearly stated in the sentence (not inferred or vague)
        - Are not duplicated or restated in a different way
        Limit to a maximum of 1 triple per sentence.
        If no valid triples are found, return: No related entities and relations.




        Output as a JSON array of objects with keys: "subject", "predicate", "object".

        Do not add any explanation. Just return valid JSON.

        Now extract from this:
        \"\"\"{{text}}\"\"\"
        """
        self.valid_triples = []
        self.chunk_data = []

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
            sentences = sent_tokenize(chunk_text)
            

            for i, sentence in enumerate(sentences):
                if len(sentence.strip()) < 40:
                    continue  # skip short or uninformative lines
                if self.rule_based_filter(sentence) or self.is_relevant_with_ner(sentence):
                      # Skip unimportant sentences

                    try:
                        prompt = self.prompt_template.format(text=sentence)
                        print(f"\n--- Page {page_no} | Sentence {i} ---")
                        print("Prompt sent to LLM:")
                        

                        response = self.llm.invoke(prompt)
                        print("Raw LLM response:")
                        print(response)
                        triples = json.loads(response)
                        chunk_results.append((sentence,page_no, i,))
                        continue
                        # for t in triples:
                        #     if not all(isinstance(t.get(k), str) for k in ("subject", "predicate", "object")):
                        #         print(f" Skipping invalid triple (non-string values): {t}")
                        #         continue

                        #     if self._is_valid_triple(t):
                               
                        #         print(f"{t['subject']} —{t['predicate']}→ {t['object']}")
                        #         break
                        #     else:
                        #         print(f"Suspicious triple: {t}")
                                
                        

                    except Exception as e:
                        print(f"LLM error on page {page_no} sentence {i}: {e}")
        return chunk_results

    def build_dict(self, chunk_results):
        self.chunk_data = []
        for sentence, page_no, i in chunk_results:
            self.chunk_data.append({
                "context": sentence,
                "technique": None,
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
    extractor = CyberTripleExtractor("cti-analysis/Extraction-master/Extraction-master/AnalysisOfCyberattackOnUS.pdf")
    raw_chunk_results = extractor.run()
    extractor.build_dict(raw_chunk_results)
    extractor.save_to_json("chunk_data.json")