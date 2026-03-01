import os
import openai
from dotenv import load_dotenv

def test_connection():
    # Load .env
    load_dotenv()
    
    api_key = os.getenv("SYNTHESIZER_API_KEY")
    base_url = os.getenv("SYNTHESIZER_BASE_URL")
    model = os.getenv("SYNTHESIZER_MODEL")
    
    print(f"Testing LLM Connection:")
    print(f"  Backend:  openai_api")
    print(f"  Base URL: {base_url}")
    print(f"  Model:    {model}")
    print(f"  Key:      {api_key[:5]}...{api_key[-4:] if api_key else 'None'}")
    
    if not api_key:
        print("Error: SYNTHESIZER_API_KEY is missing!")
        return

    client = openai.OpenAI(
        api_key=api_key,
        base_url=base_url
    )
    
    try:
        print("\nListing available models...")
        models = client.models.list()
        print(f"Found {len(models.data)} models. Listing all:")
        for m in models.data:
            print(f" - {m.id}")
            
        print("\nSending request...")
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Say 'Connection Successful' if you can hear me." }],
            max_tokens=20
        )
        print("\n[SUCCESS] Connection Established.")
        print(f"Response: {response.choices[0].message.content}")
        
    except Exception as e:
        print(f"\n[FAILURE] Connection Failed.")
        print(f"Error: {e}")

if __name__ == "__main__":
    test_connection()