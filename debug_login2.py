import sys
sys.path.insert(0, 'src')
import urllib.request, urllib.parse, re
from http.cookiejar import CookieJar, DefaultCookiePolicy

policy = DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainLiberal)
jar = CookieJar(policy=policy)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'Mozilla/5.0')]

resp = opener.open('http://192.168.56.101:8080/login.php', timeout=10)
body = resp.read().decode('utf-8', errors='replace')

print('=== Cookies after GET /login.php ===')
for c in jar:
    print(f'  {c.name}={c.value[:16]}  domain={c.domain}  path={c.path}  secure={c.secure}')

print()
print('=== user_token search ===')
m = re.search(r'name="user_token"\s+value="([^"]+)"', body)
print('regex1 (with name=):', m.group(1) if m else None)
m2 = re.search(r'user_token[^>]*value="([a-f0-9]+)"', body)
print('regex2 (loose):', m2.group(1) if m2 else None)

# Print the form HTML
fm = re.search(r'<form[^>]*>.*?</form>', body, re.S)
if fm:
    print()
    print('=== Form HTML ===')
    print(fm.group(0)[:1500])
else:
    print('NO FORM FOUND in page')
    print('First 1000 chars of body:')
    print(body[:1000])
