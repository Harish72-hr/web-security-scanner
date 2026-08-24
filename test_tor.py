import requests

proxies = {
    "http": "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150"
}

try:

    response = requests.get(
        "https://check.torproject.org/api/ip",
        proxies=proxies,
        timeout=30
    )

    print(response.text)

except Exception as e:

    print("Error:", e)