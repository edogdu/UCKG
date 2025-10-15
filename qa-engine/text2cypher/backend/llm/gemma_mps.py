"""Mac-GPU loader and inference helper for Neo4j Text-to-Cypher Gemma model."""

from typing import Tuple
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

HF_MODEL_ID = "neo4j/text2cypher-gemma-2-9b-it-finetuned-2024v1"
PROMPT_TEMPLATE = (
    "Generate a Cypher query that answers the user question.\n"
    "Use only the relationship types and properties present in the schema.\n"
    "Schema: {schema}\nQuestion: {question}\nCypher output:"
)

def load_model():
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch

    tokenizer = AutoTokenizer.from_pretrained(HF_MODEL_ID)

    # 1️⃣ Load base + LoRA ENTIRELY on CPU, no dispatch, no accelerate
    model = AutoModelForCausalLM.from_pretrained(
        HF_MODEL_ID,
        torch_dtype=torch.bfloat16,
        device_map=None,            # <- disables accelerate dispatch
        low_cpu_mem_usage=False,    # load normally so PEFT keeps it on CPU
    )

    # 2️⃣ Cast ALL tensors to fp16
    for p in model.parameters():
        if p.dtype == torch.bfloat16:
            p.data = p.data.to(torch.float16)

    # 3️⃣ Move to Mac GPU
    model.to("mps").eval()
    return tokenizer, model
def _clean(output: str) -> str:
    output = output.partition("**Explanation:**")[0]
    output = output.strip("`\n ").lstrip("cypher").strip()
    return output

def generate(tokenizer, model, question: str, schema: str, **kw) -> str:
    prompt = PROMPT_TEMPLATE.format(schema=schema, question=question)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        tokens = model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=kw.get("temperature", 0.2),
            top_p=kw.get("top_p", 0.9),
            pad_token_id=tokenizer.eos_token_id,
        )
    text = tokenizer.decode(tokens[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    return _clean(text)