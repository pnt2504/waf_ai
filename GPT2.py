import requests

API_KEY = "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"

url = "https://openrouter.ai/api/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    # 2 header dưới là optional nhưng nên có
    "HTTP-Referer": "https://your-site-or-app.com",
    "X-Title": "My GitHub Bot",
}

data = {
    "model": "openai/gpt-4o-mini",
    "messages": [
        {"role": "user", "content": "giải toán 1 + 2 = ?"}
    ],
}

resp = requests.post(url, headers=headers, json=data)
print(resp.json()["choices"][0]["message"]["content"])
