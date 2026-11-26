// CipherDrop protocol v1 example client for C# / .NET 8+.
//
// Encrypts locally with System.Security.Cryptography.AesGcm; only ciphertext is
// uploaded and the key lives in the URL fragment (#v1.<key>).
// Password-protected shares need Argon2id, which .NET does not ship; this example
// creates password-less shares and refuses to decrypt password-protected ones.
//
//   dotnet run -- create https://paste.example.com < secret.txt
//   dotnet run -- read < link.txt
//   dotnet run -- vectors ../../crates/protocol/testdata/vectors.json

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

static class Program
{
    const string AadNone = "cipherdrop/v1;alg=AES-256-GCM;kdf=none";

    static async Task<int> Main(string[] args)
    {
        try
        {
            switch (args.FirstOrDefault())
            {
                case "create" when args.Length >= 2:
                    {
                        var secret = await Console.In.ReadToEndAsync();
                        var url = await CreateAsync(args[1], secret, ttlSeconds: 3600, maxReads: 1);
                        Console.WriteLine(url);
                        return 0;
                    }
                case "read":
                    {
                        var link = (Console.In.ReadLine() ?? "").Trim();
                        Console.Write(await ReadAsync(link));
                        return 0;
                    }
                case "vectors" when args.Length >= 2:
                    return Vectors(args[1]);
                default:
                    Console.Error.WriteLine("usage: create <server> | read | vectors <vectors.json>");
                    return 2;
            }
        }
        catch (Exception e) when (e is CryptographicException or HttpRequestException or FormatException or InvalidOperationException)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 1;
        }
    }

    // ---------------------------------------------------------------- encoding

    static string B64(ReadOnlySpan<byte> b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] UnB64(string s, int expected = -1)
    {
        if (!Regex.IsMatch(s, "^[A-Za-z0-9_-]*$") || s.Length % 4 == 1) throw new FormatException("malformed base64url");
        var t = s.Replace('-', '+').Replace('_', '/');
        t += new string('=', (4 - t.Length % 4) % 4);
        var b = Convert.FromBase64String(t);
        if (B64(b) != s) throw new FormatException("non-canonical base64url");
        if (expected >= 0 && b.Length != expected) throw new FormatException("wrong length");
        return b;
    }

    // ---------------------------------------------------------------- crypto

    public static JsonObject Encrypt(byte[] key, byte[] plaintext, byte[]? nonce = null)
    {
        nonce ??= RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(nonce, plaintext, ct, tag, Encoding.ASCII.GetBytes(AadNone));
        return new JsonObject
        {
            ["version"] = 1,
            ["algorithm"] = "AES-256-GCM",
            ["nonce"] = B64(nonce),
            ["ciphertext"] = B64([.. ct, .. tag]),
        };
    }

    public static byte[] Decrypt(byte[] key, JsonNode env)
    {
        if ((int?)env["version"] != 1 || (string?)env["algorithm"] != "AES-256-GCM")
            throw new InvalidOperationException("unsupported envelope");
        if (env["kdf"] is not null)
            throw new InvalidOperationException("password-protected share: use the CLI, the Python client or an SDK");
        var nonce = UnB64((string)env["nonce"]!, 12);
        var data = UnB64((string)env["ciphertext"]!);
        if (data.Length < 16) throw new FormatException("ciphertext too short");
        var pt = new byte[data.Length - 16];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, data.AsSpan(0, data.Length - 16), data.AsSpan(data.Length - 16), pt, Encoding.ASCII.GetBytes(AadNone));
        return pt;
    }

    static byte[] Payload(string content)
    {
        var json = Encoding.UTF8.GetBytes(new JsonObject { ["content"] = content }.ToJsonString());
        var padded = new byte[(json.Length + 255) / 256 * 256];
        Array.Fill(padded, (byte)' ');
        json.CopyTo(padded, 0);
        CryptographicOperations.ZeroMemory(json);
        return padded;
    }

    // ---------------------------------------------------------------- HTTP

    static HttpClient Http(string? apiKey)
    {
        // HttpClient validates TLS certificates by default; no custom validation callback is installed.
        var h = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        h.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrEmpty(apiKey)) h.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        return h;
    }

    static void RequireHttps(string server)
    {
        var insecureOk = Environment.GetEnvironmentVariable("CIPHERDROP_ALLOW_INSECURE_HTTP") == "1";
        if (!server.StartsWith("https://") && !(insecureOk && server.StartsWith("http://")))
            throw new InvalidOperationException("refusing non-HTTPS server URL");
    }

    static async Task<string> CreateAsync(string server, string secret, int ttlSeconds, int maxReads)
    {
        server = server.TrimEnd('/');
        RequireHttps(server);
        var key = RandomNumberGenerator.GetBytes(32);
        var pt = Payload(secret);
        try
        {
            var body = Encrypt(key, pt);
            body["ttl_seconds"] = ttlSeconds;
            body["max_reads"] = maxReads;
            using var http = Http(Environment.GetEnvironmentVariable("CIPHERDROP_API_KEY"));
            using var res = await http.PostAsync($"{server}/api/v1/shares",
                new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"));
            var text = await res.Content.ReadAsStringAsync();
            if (!res.IsSuccessStatusCode) throw new HttpRequestException($"HTTP {(int)res.StatusCode}: {text}");
            var url = (string)JsonNode.Parse(text)!["url"]!;
            return $"{url}#v1.{B64(key)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(pt);
        }
    }

    static async Task<string> ReadAsync(string link)
    {
        var m = Regex.Match(link, "^(https?://.+)/s/([A-Za-z0-9_-]{22})#v1\\.([A-Za-z0-9_-]{43})$");
        if (!m.Success) throw new FormatException("malformed share link");
        var server = m.Groups[1].Value;
        RequireHttps(server);
        var key = UnB64(m.Groups[3].Value, 32);
        try
        {
            using var http = Http(Environment.GetEnvironmentVariable("CIPHERDROP_API_KEY"));
            // Consume exactly once; never retried.
            using var res = await http.PostAsync($"{server}/api/v1/shares/{m.Groups[2].Value}/consume",
                new StringContent("{}", Encoding.UTF8, "application/json"));
            var text = await res.Content.ReadAsStringAsync();
            if (!res.IsSuccessStatusCode) throw new HttpRequestException($"HTTP {(int)res.StatusCode}: {text}");
            var pt = Decrypt(key, JsonNode.Parse(text)!);
            return (string)JsonNode.Parse(pt)!["content"]!;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    // ---------------------------------------------------------------- vectors

    static int Vectors(string path)
    {
        var doc = JsonNode.Parse(File.ReadAllText(path))!;
        foreach (var v in doc["vectors"]!.AsArray())
        {
            var name = (string)v!["name"]!;
            if (v["password"] is not null) { Console.WriteLine($"skip valid    {name} (requires Argon2id)"); continue; }
            var key = UnB64((string)v["key"]!, 32);
            var env = v["envelope"]!;
            var pt = Encoding.UTF8.GetString(Decrypt(key, env));
            if (pt != (string)v["plaintext"]!) throw new InvalidOperationException($"{name}: plaintext mismatch");
            var again = Encrypt(key, Encoding.UTF8.GetBytes(pt), UnB64((string)env["nonce"]!, 12));
            if ((string)again["ciphertext"]! != (string)env["ciphertext"]!) throw new InvalidOperationException($"{name}: re-encryption mismatch");
            Console.WriteLine($"ok   valid    {name}");
        }
        foreach (var v in doc["invalid"]!.AsArray())
        {
            var name = (string)v!["name"]!;
            try { Decrypt(UnB64((string)v["key"]!, 32), v["envelope"]!); }
            catch (Exception e) when (e is CryptographicException or FormatException or InvalidOperationException)
            {
                Console.WriteLine($"ok   invalid  {name}");
                continue;
            }
            throw new InvalidOperationException($"{name}: expected failure");
        }
        return 0;
    }
}
