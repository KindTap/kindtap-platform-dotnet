using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace KindTap
{
    public class Http
    {
        private static string ALGO_PRE = "KT1";
        private static string ALGO = String.Format("{0}-HMAC-SHA256", ALGO_PRE);
        private static string AUTH_TYPE = String.Format("{0}_request", ALGO_PRE.ToLower());
        private static string REGION = "us";

        private static string EQUALS_ENC = Uri.EscapeDataString("=");

        private static Regex EQUALS_EXPR = new Regex("=");
        private static Regex MULTI_WS_EXPR = new Regex("[ ][ ]+");

        private static SHA256 sha256 = SHA256.Create();

        private static string buildCanonHeaders(Dictionary<string, string> headers)
        {
            SortedDictionary<string, string> sortedHeaders = new SortedDictionary<string, string>();
            foreach (var h in headers)
            {
                sortedHeaders.Add(h.Key.ToLower(), MULTI_WS_EXPR.Replace(h.Value.Trim(), " "));
            }
            string canonHeaders = "";
            foreach (var h in sortedHeaders)
            {
                canonHeaders += h.Key + ":" + h.Value + "\n";
            }
            return canonHeaders;
        }

        private static string buildCanonQuery(Dictionary<string, string> queryParams) {
            SortedDictionary<string, string> sortedParams = new SortedDictionary<string, string>();
            foreach (var p in queryParams)
            {
                sortedParams.Add(p.Key, EQUALS_EXPR.Replace(p.Value, EQUALS_ENC));
            }
            List<string> queryParts = new List<string>();
            foreach (var p in sortedParams)
            {
                queryParts.Add(Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value));
            }
            return String.Join("&", queryParts);
        }

        private static string buildCanonURI(string uri)
        {
            string[] pathParts = Array.FindAll(uri.Split("/"), (string p) => p.Length > 0);
            if (pathParts.Length == 0)
            {
                return "/";
            }
            List<string> encodedParts = new List<string>();
            foreach (var p in pathParts)
            {
                encodedParts.Add(Uri.EscapeDataString(Uri.EscapeDataString(p)));
            }
            return "/" + String.Join("/", encodedParts) + "/";
        }

        private static string buildSignedHeaders(Dictionary<string, string> headers)
        {
            SortedDictionary<string, string> sortedHeaders = new SortedDictionary<string, string>();
            foreach (var h in headers)
            {
                sortedHeaders.Add(h.Key.ToLower(), "");
            }
            List<string> sortedHeaderNames = new List<string>();
            foreach (var h in sortedHeaders)
            {
                sortedHeaderNames.Add(h.Key);
            }
            return String.Join(";", sortedHeaderNames);
        }

        private static byte[] computeHMACSHA256(string message, byte[] keyBytes)
        {
            byte[] msgBytes = Encoding.UTF8.GetBytes(message.ToCharArray());
            return new HMACSHA256(keyBytes).ComputeHash(msgBytes);
        }

        private static byte[] computeSHA256(string message)
        {
            byte[] msgBytes = Encoding.UTF8.GetBytes(message.ToCharArray());
            return sha256.ComputeHash(msgBytes);
        }

        private static void debug(string message, params object[] args)
        {
#if DEBUG
            Console.WriteLine(message, args);
#endif
        }

        private static string generateSignatureV1(
            string service,
            string clientSecret,
            string requestMethod,
            string requestURI,
            DateTime requestDate,
            Dictionary<string, string> requestHeaders,
            string requestBody,
            Dictionary<string, string> requestParams
        )
        {
            string canonHeaders = buildCanonHeaders(requestHeaders);
            string canonQuery = buildCanonQuery(requestParams);
            string canonURI = buildCanonURI(requestURI);
            string signedHeaders = buildSignedHeaders(requestHeaders);

            string canonRequest = String.Join("\n", new List<string>{
              requestMethod.ToUpper(),
              canonURI,
              canonQuery,
              canonHeaders,
              signedHeaders,
              toHex(computeSHA256(requestBody))
            });
            debug(String.Format("Canonical Request: {0}", canonRequest));
            string canonRequestHash = toHex(computeSHA256(canonRequest));
            debug(String.Format("Canonical Request Hash: {0}", canonRequestHash));

            string credDate = stringifyDate(requestDate, false);
            string credScope = String.Join("/", new List<string>{
                credDate,
                REGION,
                service,
                AUTH_TYPE
            });

            string msgToSign = String.Join("\n", new List<string>{
              ALGO,
              stringifyDate(requestDate),
              credScope,
              canonRequestHash
            });
            debug(String.Format("Message to Sign: {0}", msgToSign));

            byte[] key = Encoding.UTF8.GetBytes((ALGO_PRE + clientSecret).ToCharArray());

            byte[] k0 = computeHMACSHA256(credDate, key);
            byte[] k1 = computeHMACSHA256(REGION, k0);
            byte[] k2 = computeHMACSHA256(service, k1);
            byte[] k3 = computeHMACSHA256(AUTH_TYPE, k2);

            string signature = toHex(computeHMACSHA256(msgToSign, k3));
            debug(String.Format("Signature: {0}", signature));

            return signature;
        }

        public static string generateSignedAuthHeader(
            string service,
            string clientKey,
            string clientSecret,
            string requestMethod,
            string requestURI,
            DateTime requestDate,
            Dictionary<string, string> requestHeaders,
            string requestBody,
            Dictionary<string, string> requestParams
        )
        {
            string credDate = stringifyDate(requestDate, false);
            string credScope = String.Join("/", new List<string>{
                credDate,
                REGION,
                service,
                AUTH_TYPE
            });
            string signedHeaders = buildSignedHeaders(requestHeaders);

            string signature = generateSignatureV1(
              service,
              clientSecret,
              requestMethod,
              requestURI,
              requestDate,
              requestHeaders,
              requestBody,
              requestParams
            );

            string auth = ALGO + " Credential=" + clientKey + "/" + credScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
            debug(String.Format("Authorization: {0}", auth));

            return auth;
        }

        public static string stringifyDate(DateTime date, bool? full = true)
        {
            if (!(bool)full)
            {
                return date.ToString("yyyyMMdd");
            }
            return date.ToString("yyyyMMddTHHmmssZ");
        }

        private static string toHex(byte[] data)
        {
            string s = "";
            foreach (var b in data)
            {
                s += b.ToString("x2");
            }
            return s;
        }
    }
}
