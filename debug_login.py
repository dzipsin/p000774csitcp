import sys
sys.path.insert(0, 'src')
import urllib.request, urllib.parse, re
from http.cookiejar import CookieJar

jar = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'Mozilla/5.0 (SOC-Triage-Evaluator)')]

# Step 1: GET login page
resp = opener.open('http://192.168.56.101:8080/login.php', timeout=10)
body = resp.read().decode('utf-8', errors='replace')
print('=== GET /login.php ===')
print('Final URL :', resp.geturl())
print('Cookies   :', [(c.name, c.value[:12]+'...') for c in jar])

m = re.search(r'name="user_token"\s+value="([^"]+)"', body)
token = m.group(1) if m else None
print('user_token:', token)

# Step 2: POST credentials
data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
if token: data['user_token'] = token
encoded = urllib.parse.urlencode(data).encode()
req = urllib.request.Request('http://192.168.56.101:8080/login.php', data=encoded, method='POST')
resp2 = opener.open(req, timeout=10)
body2 = resp2.read().decode('utf-8', errors='replace')

print()
print('=== POST /login.php ===')
print('Final URL :', resp2.geturl())
print('Status    :', resp2.status)
print('Cookies   :', [(c.name, c.value[:12]+'...') for c in jar])
print('Body snippet:', body2[:500])
print()
print('login.php in final URL?', 'login.php' in resp2.geturl())
print('Body contains "Login failed"?', 'login failed' in body2.lower())
print('Body contains "Welcome"?', 'welcome' in body2.lower())
