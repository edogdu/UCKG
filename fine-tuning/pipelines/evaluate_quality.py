import json
import os
import glob
import time
from dotenv import load_dotenv
from openai import OpenAI

# Load .env
load_dotenv()

# Configuration
API_KEY = os.getenv("SYNTHESIZER_API_KEY")
BASE_URL = os.getenv("SYNTHESIZER_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
MODEL = os.getenv("SYNTHESIZER_MODEL", "gemini-2.0-flash-lite-001") # Default to Lite

if not API_KEY:
    print("Error: SYNTHESIZER_API_KEY not found in .env")
    exit(1)

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL
)

JUDGE_PROMPT = """You are an expert Cybersecurity Instructor. 
Grade the following Q&A pair generated for an Incident Response training dataset.

Criteria:
1. Accuracy: Is the technical information correct?
2. Completeness: Does it include Definition, Technique, and Mitigation (if applicable)?
3. Clarity: Is it written in natural, professional language?

Input:
Question: {question}
Answer: {answer}

Output format:
Score: [1-5]
Reasoning: [Brief explanation]
"""

def find_latest_output():
    output_dirs = sorted(glob.glob("cache/output/*"), reverse=True)
    if not output_dirs:
        return None
    
    # Look for generate/atomic_sharegpt.jsonl
    latest_dir = output_dirs[0]
    jsonl_path = os.path.join(latest_dir, "generate", "atomic_sharegpt.jsonl")
    
    # Try finding any jsonl if specific name fails
    if not os.path.exists(jsonl_path):
        files = glob.glob(os.path.join(latest_dir, "generate", "*.jsonl"))
        if files:
            return files[0]
            
    return jsonl_path

def evaluate():
    file_path = find_latest_output()
    if not file_path or not os.path.exists(file_path):
        print("No output file found to evaluate.")
        return

    print(f"Evaluating: {file_path}")
    print(f"Using Judge Model: {MODEL}")
    print("-" * 50)

    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Limit to first 5 to save time/cost
    for i, line in enumerate(lines[:5]):
        try:
            data = json.loads(line)
            question = ""
            answer = ""

            # Parse ShareGPT format
            if "conversations" in data:
                for msg in data["conversations"]:
                    if msg['from'] == 'human':
                        question = msg['value']
                    elif msg['from'] == 'gpt':
                        answer = msg['value']
            # Parse standard format
            elif "question" in data:
                question = data["question"]
                answer = data["answer"]

            if not question or not answer:
                print(f"Skipping row {i}: Could not parse Q/A")
                continue

            print(f"\n--- Item {i+1} ---")
            print(f"Q: {question[:100]}...") # Truncate for display
            
            prompt = JUDGE_PROMPT.format(question=question, answer=answer)
            
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0
            )
            
            print(f"Judge: {response.choices[0].message.content.strip()}")
            time.sleep(1) # Rate limit safety

        except Exception as e:
            print(f"Error evaluating row {i}: {e}")

if __name__ == "__main__":
    evaluate()
