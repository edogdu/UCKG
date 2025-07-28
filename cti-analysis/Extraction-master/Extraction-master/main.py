import json
from docling.document_converter import DocumentConverter
from docling_core.transforms.chunker import HierarchicalChunker
from langchain_community.llms import Ollama



class CyberTripleExtractor:
    def __init__(self, file_path, model_name="mistral"):
        self.file_path = file_path
        self.converter = DocumentConverter()
        self.chunker = HierarchicalChunker()
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
        self.malont_objects = [
            "targets", "communicatesWith", "uses", "has", "hasAlias",
            "hasVulnerability", "indicates", "exploits", "hasAuthor", "belongsTo"
        ]

        self.prompt_template = f"""
        Entity And Relationship Extraction

      
        If an entity or relationship is implied or described indirectly, 
        still extract it using the most relevant ontology term.
         Do not skip subtle references like tool updates or malware propagation mechanisms.


        Please identify the following types of entities and then extract the relationships between these extracted entities: 
        malware (e.g., 'Stuxnet'), threat type (e.g., 'ransomware'), attacker groups, and named attack tools or families.

        If there are no entities and relationships pertaining to the specified types, please state: 
        'No related entities and relations.'

        
    
        do not include labels in response. keep response format the same everytime.

        below are examples , do not label your response:
        
        Named Entities: (Entity, Type), (Entity, Type), ...
        Relationships: (Subject, Verb, Object) 
        only include the output, dont use "subject,verb,and object as labels when output"

        Use simple natural types like 'attacker', 'tool', 'malware'.
        Use natural language verbs like 'uses', 'targets', 'adds', etc.

        Now analyze only the provided text and return only the output:

        \"\"\"{{text}}\"\"\"
        """


        self.chunk_data = []



    def run(self):
        print("Loading and converting document...")
        result = self.converter.convert(self.file_path)
        doc = result.document

        print("Chunking document...")
        chunks = list(self.chunker.chunk(dl_doc=doc))

        chunk_results = []


        print("Extracting triples...")
        for i, chunk in enumerate(chunks):
            chunk_text = str(chunk)
            print(f"\n--- Chunk {i + 1} ---")
            try:
                prompt = self.prompt_template.format(text=chunk_text)
                response = self.llm.invoke(prompt)

                print("Raw LLM response:")
                print(response)

                chunk_results.append((i,chunk_text,response))


            except Exception as e:
                print(f"Error parsing chunk {i + 1}: {e}")
            return chunk_results

    def build_dict(self,chunk_results):
        self.chunk_data = []
        for i,text,llm_response in chunk_results:
            self.chunk_data.append({
                "chunk_index" : i,
                "chunk_text": text,
                "llm_response/triples": llm_response,
                "context": {
                    "source_file": self.file_path,
                    "estimated_section": f"Chunk {i + 1}",
                }
            })
        return self.chunk_data

    def save_to_json(self, output_path = "chunk_data.json"):
        try:
            with open (output_path, "w", encoding="utf-8") as f:
                json.dump(self.chunk_data,f,indent = 2, ensure_ascii= False)
            print("file saved")
        except Exception as e:
            print("failed")




if __name__ == "__main__":
    extractor = CyberTripleExtractor("sample2.pdf")
    raw_chunk_results = extractor.run()
    extractor.build_dict(raw_chunk_results)
    extractor.save_to_json("chunk_data.json")



