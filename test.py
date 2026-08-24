from header_scan import scan_headers

result = scan_headers("https://google.com")

for key, value in result.items():
    print(f"{key}: {value}")