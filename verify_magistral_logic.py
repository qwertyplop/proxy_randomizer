import json

def test_parsing():
    # Load the sample response
    with open('magistral.txt', 'r', encoding='utf-8') as f:
        body = json.load(f)

    print("Original Body Loaded.")
    
    choices = body.get("choices", [])
    if choices:
        msg = choices[0].get("message", {})
        inner_content = msg.get("content")
        
        print(f"Inner content type: {type(inner_content)}")
        
        if isinstance(inner_content, list):
            # Transform Magistral Structured Content
            final_text = ""
            for item in inner_content:
                if item.get("type") == "thinking":
                    # Extract thinking text
                    think_text = ""
                    if "thinking" in item and isinstance(item["thinking"], list):
                        for t_item in item["thinking"]:
                            if t_item.get("type") == "text":
                                think_text += t_item.get("text", "")
                    elif "thinking" in item and isinstance(item["thinking"], str):
                        think_text = item["thinking"]
                        
                    final_text += f"<think>{think_text}</think>\n"
                    
                elif item.get("type") == "text":
                    final_text += item.get("text", "")
            
            print("\n--- Transformed Content Start ---")
            print(final_text[:500] + "...") # Print first 500 chars
            print("--- Transformed Content End ---")
            
            if "<think>" in final_text and "</think>" in final_text:
                print("\n✅ SUCCESS: <think> tags found.")
            else:
                print("\n❌ FAILURE: <think> tags missing.")
        else:
            print("Content is not a list.")
    else:
        print("No choices found.")

if __name__ == "__main__":
    test_parsing()
def test_parsing():
    # Load the sample response
    with open('magistral.txt', 'r', encoding='utf-8') as f:
        body = json.load(f)

    print("Original Body Loaded.")
    
    choices = body.get("choices", [])
    if choices:
        msg = choices[0].get("message", {})
        inner_content = msg.get("content")
        
        print(f"Inner content type: {type(inner_content)}")
        
        if isinstance(inner_content, list):
            # Transform Magistral Structured Content
            final_text = ""
            for item in inner_content:
                if item.get("type") == "thinking":
                    # Extract thinking text
                    think_text = ""
                    if "thinking" in item and isinstance(item["thinking"], list):
                        for t_item in item["thinking"]:
                            if t_item.get("type") == "text":
                                think_text += t_item.get("text", "")
                    elif "thinking" in item and isinstance(item["thinking"], str):
                        think_text = item["thinking"]
                        
                    final_text += f"<think>{think_text}</think>\n"
                    
                elif item.get("type") == "text":
                    final_text += item.get("text", "")
            
            print("\n--- Transformed Content Start ---")
            print(final_text[:500] + "...") # Print first 500 chars
            print("--- Transformed Content End ---")
            
            if "<think>" in final_text and "</think>" in final_text:
                print("\n✅ SUCCESS: <think> tags found.")
            else:
                print("\n❌ FAILURE: <think> tags missing.")
        else:
            print("Content is not a list.")
    else:
        print("No choices found.")

if __name__ == "__main__":
    test_parsing()
