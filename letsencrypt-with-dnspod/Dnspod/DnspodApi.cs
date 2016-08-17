using io.nulldata.letsencrypt_with_dnspod.Dnspod.Domain;
using io.nulldata.letsencrypt_with_dnspod.Dnspod.Record;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
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
            {
                token = System.Configuration.ConfigurationManager.AppSettings["Dnspod.Token"];
            }
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

        /// <summary>
        /// 
        /// </summary>
        /// <see cref="http://stackoverflow.com/questions/11846705/get-spf-records-from-a-domain"/>
        /// <param name="name"></param>
        /// <returns></returns>
        public static String DnsGetTxtRecord(String name)
        {
            const Int16 DNS_TYPE_TEXT = 0x0010;
            const Int32 DNS_QUERY_STANDARD = 0x00000100 | 0x00000008;
            const Int32 DNS_ERROR_RCODE_NAME_ERROR = 9003;
            const Int32 DNS_INFO_NO_RECORDS = 9501;
            var queryResultsSet = IntPtr.Zero;
            try
            {
                var dnsStatus = DnsQuery(
                  name,
                  DNS_TYPE_TEXT,
                  DNS_QUERY_STANDARD,
                  IntPtr.Zero,
                  ref queryResultsSet,
                  IntPtr.Zero
                );
                if (dnsStatus == DNS_ERROR_RCODE_NAME_ERROR || dnsStatus == DNS_INFO_NO_RECORDS)
                    return null;
                if (dnsStatus != 0)
                    throw new Win32Exception(dnsStatus);
                DnsRecordTxt dnsRecord;
                for (var pointer = queryResultsSet; pointer != IntPtr.Zero; pointer = dnsRecord.pNext)
                {
                    dnsRecord = (DnsRecordTxt)Marshal.PtrToStructure(pointer, typeof(DnsRecordTxt));
                    if (dnsRecord.wType == DNS_TYPE_TEXT)
                    {
                        var lines = new List<String>();
                        var stringArrayPointer = pointer
                          + Marshal.OffsetOf(typeof(DnsRecordTxt), "pStringArray").ToInt32();
                        for (var i = 0; i < dnsRecord.dwStringCount; ++i)
                        {
                            var stringPointer = (IntPtr)Marshal.PtrToStructure(stringArrayPointer, typeof(IntPtr));
                            lines.Add(Marshal.PtrToStringUni(stringPointer));
                            stringArrayPointer += IntPtr.Size;
                        }
                        return String.Join(Environment.NewLine, lines);
                    }
                }
                return null;
            }
            finally
            {
                const Int32 DnsFreeRecordList = 1;
                if (queryResultsSet != IntPtr.Zero)
                    DnsRecordListFree(queryResultsSet, DnsFreeRecordList);
            }
        }

        [DllImport("Dnsapi.dll", EntryPoint = "DnsQuery_W", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        static extern Int32 DnsQuery(String lpstrName, Int16 wType, Int32 options, IntPtr pExtra, ref IntPtr ppQueryResultsSet, IntPtr pReserved);

        [DllImport("Dnsapi.dll")]
        static extern void DnsRecordListFree(IntPtr pRecordList, Int32 freeType);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DnsRecordTxt
        {
            public IntPtr pNext;
            public String pName;
            public Int16 wType;
            public Int16 wDataLength;
            public Int32 flags;
            public Int32 dwTtl;
            public Int32 dwReserved;
            public Int32 dwStringCount;
            public String pStringArray;
        }
    }
}
