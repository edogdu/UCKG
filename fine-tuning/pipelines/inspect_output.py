import json
import glob
import os

def inspect_output():
    # Find the latest output directory
    output_dirs = sorted(glob.glob("cache/output/*"), reverse=True)
    if not output_dirs:
        print("No output found in cache/output/")
        return
        
    latest_dir = output_dirs[0]
    generate_dir = os.path.join(latest_dir, "generate")
    
    print(f"Inspecting output from: {generate_dir}")
    
    # Find JSONL files
    files = glob.glob(os.path.join(generate_dir, "*.jsonl"))
    for fpath in files:
        print(f"\n--- File: {os.path.basename(fpath)} ---")
        with open(fpath, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # GraphGen usually outputs {question: ..., answer: ...}
                    # Or sometimes formatted as ChatML {messages: ...}
                    
                    if "question" in data:
                        print(f"\n[Q]: {data['question']}")
                        print(f"[A]: {data['answer']}")
                    elif "conversations" in data:
                        # ShareGPT format
                        for msg in data["conversations"]:
                            role = msg['from'].upper()
                            content = msg['value']
                            print(f"\n[{role}]:")
                            print(content)
                    elif "messages" in data:
                        # ChatML format
                        for msg in data["messages"]:
                            role = msg['role'].upper()
                            content = msg['content']
                            print(f"\n[{role}]: {content}")
                    else:
                        print(f"\n[RAW]: {data}")
                        
                    print("-" * 40)
                except json.JSONDecodeError:
                    print("Error parsing line.")

if __name__ == "__main__":
    inspect_output()
