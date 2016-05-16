using io.nulldata.letsencrypt_with_dnspod.Dnspod.Domain;
using io.nulldata.letsencrypt_with_dnspod.Dnspod.Record;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod.Dnspod
{
    public class DnspodApi
    {
        public static readonly Uri uri = new Uri("https://dnsapi.cn/");
        public string token { get; private set; }

        public DomainApi Domain { get; private set; }

        public RecordApi Record { get; private set; }

        public DnspodApi(string token = null)
        {
            if (string.IsNullOrWhiteSpace(token))
                token = System.Configuration.ConfigurationManager.AppSettings["Dnspod.Token"];
            this.token = token;
            Domain = new DomainApi(this);
            Record = new RecordApi(this);
        }

        /// <summary>
        /// POST 操作
        /// </summary>
        /// <typeparam name="T">返回对象json</typeparam>
        /// <param name="uri">BaseAddress</param>
        /// <param name="requestUri">方法</param>
        /// <param name="content">提交内容</param>
        /// <param name="onError">HTTP 错误时处理</param>
        /// <returns></returns>
        internal static async Task<T> post<T>(string requestUri, HttpContent content)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = uri;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("User-Agent", "letsencrypt_with_dnspod/1.0.0 (hetaoos@gmail.com)");

                var response = await client.PostAsync(requestUri, content);
                if (response.IsSuccessStatusCode)
                    return await response.Content.ReadAsAsync<T>();
                return default(T);
            }
        }


        /// <summary>
        /// GET 操作
        /// </summary>
        /// <typeparam name="T">返回对象json</typeparam>
        /// <param name="uri">BaseAddress</param>
        /// <param name="requestUri">方法</param>
        /// <param name="content">提交内容</param>
        /// <param name="onError">HTTP 错误时处理</param>
        /// <returns></returns>
        internal static async Task<T> get<T>(string requestUri, NameValueCollection content = null)
        {
            if (content != null && content.Count > 0)
            {
                var q = content.ToUriQuery();
                if (string.IsNullOrEmpty(requestUri))
                    requestUri = "?" + q;
                else if (requestUri.IndexOf('?') >= 0)
                {
                    requestUri += "&" + q;
                }
                else
                    requestUri += "?" + q;
            }
            using (var client = new HttpClient())
            {
                client.BaseAddress = uri;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("User-Agent", "letsencrypt_with_dnspod/1.0.0 (hetaoos@gmail.com)");

                var response = await client.GetAsync(requestUri);
                if (response.IsSuccessStatusCode)
                    return await response.Content.JsonReadAsAsync<T>();
                return default(T);
            }
        }


        internal Dictionary<string, string> getArgs(IEnumerable<KeyValuePair<string, string>> otherValues = null)
        {
            var args = new Dictionary<string, string>();
            args["login_token"] = token;
            args["format"] = "json";

            if (otherValues != null && otherValues.Count() > 0)
            {
                foreach (var kv in otherValues)
                    args[kv.Key] = kv.Value;
            }
            return args;
        }

        internal NameValueCollection getNameValueCollection(IEnumerable<KeyValuePair<string, string>> otherValues = null)
        {
            var args = new NameValueCollection();
            args["login_token"] = token;
            args["format"] = "json";
            if (otherValues != null && otherValues.Count() > 0)
            {
                foreach (var kv in otherValues)
                    args.Add(kv.Key, kv.Value);
            }
            return args;
        }
    }
}
