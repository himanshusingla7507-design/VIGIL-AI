from phishing_detector import predict_url

urls = [
    'https://fast.com/',
    'https://google.com',
    'https://github.com',
    'https://microsoft.com',
    'https://apple.com',
    'https://amazon.com',
    'https://python.org',
    'https://cloudflare.com',
    'https://paypal-login.example.com/verify-account',
    'http://secure-bank-login.example.com/update-account',
    'http://microsoft-security.example.com/login',
    'http://free-iphone-winner.example.com/claim',
    'http://account-verify.example.com/signin/password',
]

for url in urls:
    result = predict_url(url)
    print(url)
    print(result['label'], result['probability'], result['risk_score'])
    print('---')
