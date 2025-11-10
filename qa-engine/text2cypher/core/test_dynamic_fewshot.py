"""
Test Dynamic Few-Shot Selection

Demonstrates how the enhanced T2CSS pipeline automatically selects
the most relevant few-shot examples for each query.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'llm'))

from t2css_enhanced import EnhancedT2CSSPipeline

try:
    from ollama_llm import OllamaLLM
except ImportError:
    OllamaLLM = None  # LLM tests will be skipped


def test_dynamic_fewshot_selection():
    """Test dynamic few-shot selection with various query types"""
    
    print("="*80)
    print("DYNAMIC FEW-SHOT SELECTION TEST")
    print("="*80)
    
    # Initialize pipeline (automatically loads 45 few-shot candidates)
    pipeline = EnhancedT2CSSPipeline(
        top_k=10,
        fewshot_k=2,  # Select top-2 most relevant examples
        auto_load_fewshot=True
    )
    
    # Test queries from different categories
    test_cases = [
        {
            "category": "Node Lookup",
            "question": "Get details for CVE-2021-44228"
        },
        {
            "category": "Aggregation",
            "question": "Count how many techniques are used by APT28"
        },
        {
            "category": "Multi-hop",
            "question": "What mitigations exist for techniques used by FIN7's toolset?"
        },
        {
            "category": "Path Query",
            "question": "Find the shortest path between Mimikatz and Lazarus Group"
        },
        {
            "category": "Conditional",
            "question": "Show me critical CVEs that don't require user interaction"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*80}")
        print(f"TEST {i}: {test_case['category']}")
        print(f"Question: {test_case['question']}")
        print("="*80)
        
        # Generate prompt (without LLM)
        prompt = pipeline.generate_cypher(test_case['question'])
        
        # Extract and display the few-shot examples from the prompt
        print("\n" + "-"*80)
        print("SELECTED FEW-SHOT EXAMPLES:")
        print("-"*80)
        
        # Find the few-shot section in the prompt
        if "EXAMPLE NL:" in prompt:
            examples_section = prompt.split("Few-shot Examples:")[1].split("Question:")[0]
            print(examples_section.strip())
        else:
            print("No few-shot examples in prompt")
        
        print("\n" + "-"*80)
        print("INTENT & SCAFFOLD:")
        print("-"*80)
        
        # Extract intent and scaffold
        if "Clause Scaffold:" in prompt:
            scaffold_section = prompt.split("Clause Scaffold:")[1].split("Semantic Schema")[0]
            print(scaffold_section.strip())
    
    print("\n" + "="*80)
    print("✅ Dynamic Few-Shot Selection Test Complete!")
    print("="*80)
    print("\nKey Observations:")
    print("- Each query gets 2 most relevant examples from the 45 candidates")
    print("- Examples are selected based on semantic similarity")
    print("- Intent classification guides both scaffold and example selection")
    print("- Reduces prompt size while maintaining quality")


def test_with_llm_generation():
    """Test with actual LLM generation"""
    
    print("\n\n" + "="*80)
    print("LLM GENERATION TEST WITH DYNAMIC FEW-SHOT")
    print("="*80)
    
    # Initialize pipeline and LLM
    pipeline = EnhancedT2CSSPipeline(
        top_k=10,
        fewshot_k=2,
        auto_load_fewshot=True
    )
    
    llm = OllamaLLM(model="llama3")
    
    # Test question
    question = "Find all CVEs with critical severity published in 2021"
    
    print(f"\nQuestion: {question}")
    print("\n" + "-"*80)
    print("Generating Cypher with LLM...")
    print("-"*80)
    
    try:
        cypher = pipeline.generate_cypher(
            question=question,
            llm=llm
        )
        
        print(f"\n✅ Generated Cypher:\n{cypher}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("(This is expected if Ollama is not running)")


if __name__ == "__main__":
    # Test 1: Show dynamic few-shot selection
    test_dynamic_fewshot_selection()
    
    # Test 2: Generate with LLM (optional, requires Ollama)
    print("\n\nWould you like to test with LLM generation? (requires Ollama)")
    print("Skipping LLM test for now...")
    # Uncomment to test with LLM:
    # test_with_llm_generation()

