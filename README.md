## KindTap Platform Library for C# .NET

#### This library currently supports generating a signed authorization header which is required to make requests to KindTap Platform APIs.

### Installation

Install the library via nuget: https://www.nuget.org/packages/kindtap-platform-dotnet/0.2.0

### Example using HttpClient, HttpRequestMessage and HttpResponseMessage

#### Important Notes

* the `host` and `x-kt-date` headers are required
* request body must be a string that matches exactly the body of the HTTP request
* when providing `content-type` header, note that its value must match exactly what is set in the StringContent object provided as the HttpRequestMessage' Content property
* need to include the `kindtap-platform-dotnet` nuget package in your project

```cs
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using Xunit;

namespace KindTapTest
{
    public class TestPlatformMethodTest
    {
        [Fact]
        public async void MethodTest()
        {
            HttpClient client = new HttpClient();

            string host = "kindtap-platform-host";
            string path = "/path/to/api/endpoint/";
            string service = "kindtap-platform-service-name";
            string method = "<http-method>";
            string key = "kindtap-client-key";
            string secret = "kindtap-client-secret";
            string body = "{}";

            DateTime date = DateTime.UtcNow;

            Dictionary<string, string> queryParams = new Dictionary<string, string>{
                { "key1", "value1" },
                { "key2", "1" }
            };
            List<string> queryParts = new List<string>();
            foreach (var p in queryParams)
            {
                queryParts.Add(p.Key + "=" + Uri.EscapeDataString(p.Value));
            }
            string querystring = String.Join("&", queryParts);

            Dictionary<string, string> headers = new Dictionary<string, string>{
                { "Content-Type", "application/json; charset=utf-8" },
                { "Host", host },
                { "X-KT-Date", KindTap.Http.stringifyDate(date) },
            };

            StringContent content = new StringContent(body, Encoding.UTF8, "application/json");

            string authHeader = KindTap.Http.generateSignedAuthHeader(
                service,
                key,
                secret,
                method,
                path,
                date,
                headers,
                body,
                queryParams
            );
            headers.Add("Authorization", authHeader);

            HttpRequestMessage request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://" + host + path + "?" + querystring),
                Content = content
            };
            foreach (var h in headers)
            {
                // required to add content-type
                request.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            HttpResponseMessage response = await client.SendAsync(request);

            Console.WriteLine(response.StatusCode + ": " + response.Content);

            Assert.InRange<int>((int)response.StatusCode, 200, 201);
        }
    }
}
```
