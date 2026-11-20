<!-- Part of the `sast-ssrf` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — requests

```python
# VULNERABLE: URL fully controlled by user
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

# SECURE: strict allowlist on destination host
ALLOWED = {"api.example.com"}
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    if urlparse(url).hostname not in ALLOWED:
        abort(403)
    response = requests.get(url)
    return response.text
```

### Python — urllib

```python
# VULNERABLE: user controls the URL passed to urlopen
def preview(request):
    target = request.GET.get('target')
    data = urllib.request.urlopen(target).read()
    return HttpResponse(data)

# SECURE: only allow https scheme to a hardcoded host
def preview(request):
    target = request.GET.get('target')
    parsed = urlparse(target)
    if parsed.scheme != 'https' or parsed.hostname != 'media.example.com':
        return HttpResponse(status=400)
    data = urllib.request.urlopen(target).read()
    return HttpResponse(data)
```

### Node.js — fetch / axios

```javascript
// VULNERABLE: webhook URL comes directly from request body
app.post('/webhook/test', async (req, res) => {
  const { url } = req.body;
  const result = await fetch(url);
  res.json(await result.json());
});

// SECURE: allowlist check before fetch
const ALLOWED_HOSTS = new Set(['hooks.example.com']);
app.post('/webhook/test', async (req, res) => {
  const { url } = req.body;
  const { hostname } = new URL(url);
  if (!ALLOWED_HOSTS.has(hostname)) return res.status(403).send('Forbidden');
  const result = await fetch(url);
  res.json(await result.json());
});
```

### Node.js — http.request

```javascript
// VULNERABLE: host and path from query string
app.get('/proxy', (req, res) => {
  const { host, path } = req.query;
  http.get({ host, path }, (proxyRes) => proxyRes.pipe(res));
});
```

### Ruby on Rails — Net::HTTP / OpenURI

```ruby
# VULNERABLE: open() fetches arbitrary URL
def import
  url = params[:url]
  content = URI.open(url).read  # also triggers for open(url) via Kernel#open
  # ...
end

# SECURE: restrict scheme and host
def import
  url = params[:url]
  uri = URI.parse(url)
  raise "Forbidden" unless uri.is_a?(URI::HTTPS) && uri.host == "data.example.com"
  content = uri.open.read
  # ...
end
```

### PHP — cURL

```php
// VULNERABLE: user-supplied URL piped into curl
function fetch_preview($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}
// Called as: fetch_preview($_GET['url'])

// SECURE: validate URL against allowlist before curl
function fetch_preview($url) {
    $allowed = ['https://cdn.example.com/'];
    foreach ($allowed as $prefix) {
        if (strpos($url, $prefix) === 0) {
            // ... proceed with curl
        }
    }
    throw new Exception("Destination not allowed");
}
```

### PHP — file_get_contents

```php
// VULNERABLE: file_get_contents with http:// wrapper and user input
$url = $_GET['source'];
$data = file_get_contents($url);  // fetches remote URL if scheme is http/https/ftp
```

### Java — Spring / OkHttp

```java
// VULNERABLE: RestTemplate with user-controlled URL
@GetMapping("/proxy")
public ResponseEntity<String> proxy(@RequestParam String url) {
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForEntity(url, String.class);
}

// VULNERABLE: OkHttp with user-controlled host
public String fetch(String host, String path) {
    Request request = new Request.Builder()
        .url("https://" + host + path)
        .build();
    return client.newCall(request).execute().body().string();
}
```

### Go — net/http

```go
// VULNERABLE: user-supplied URL passed to http.Get
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, err := http.Get(target)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    io.Copy(w, resp.Body)
}

// VULNERABLE: user controls host in net.Dial
func dialHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    port := r.URL.Query().Get("port")
    conn, _ := net.Dial("tcp", host+":"+port)
    // ...
}
```

### C# — HttpClient

```csharp
// VULNERABLE: user-supplied URL passed to HttpClient
[HttpGet("proxy")]
public async Task<IActionResult> Proxy([FromQuery] string url)
{
    var response = await _httpClient.GetAsync(url);
    var content = await response.Content.ReadAsStringAsync();
    return Content(content);
}
```

---

