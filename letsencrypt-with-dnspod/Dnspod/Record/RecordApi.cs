using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod.Dnspod.Record
{
    public class RecordApi
    {
        private DnspodApi framework;

        public RecordApi(DnspodApi framework)
        {
            this.framework = framework;
        }

        public async Task<DnspodRecordListResult> List(int domain_id)
        {
            var args = framework.getArgs();
            args["domain_id"] = domain_id.ToString();
            var content = new FormUrlEncodedContent(args);
            return await DnspodApi.post<DnspodRecordListResult>("Record.List", content);
        }

        /// <summary>
        /// 创建dns记录
        /// </summary>
        /// <param name="domain_id"></param>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public async Task<DnspodRecordCreateResult> Create(int domain_id, string sub_domain, string value)
        {
            var args = framework.getArgs();
            args["domain_id"] = domain_id.ToString();
            args["sub_domain"] = sub_domain;
            args["record_type"] = "TXT";
            args["record_line"] = "默认";
            args["value"] = value;
            var content = new FormUrlEncodedContent(args);
            return await DnspodApi.post<DnspodRecordCreateResult>("Record.Create", content);
        }
        public async Task<DnspodRecordCreateResult> Modify(int domain_id, int record_id, string sub_domain, string value)
        {
            var args = framework.getArgs();
            args["domain_id"] = domain_id.ToString();
            args["record_id"] = record_id.ToString();
            args["sub_domain"] = sub_domain;
            args["record_type"] = "TXT";
            args["record_line"] = "默认";
            args["value"] = value;
            var content = new FormUrlEncodedContent(args);
            return await DnspodApi.post<DnspodRecordCreateResult>("Record.Modify", content);
        }

        public async Task<DnspodResult> Remove(int domain_id, int record_id)
        {
            var args = framework.getArgs();
            args["domain_id"] = domain_id.ToString();
            args["record_id"] = record_id.ToString();
            var content = new FormUrlEncodedContent(args);
            return await DnspodApi.post<DnspodRecordCreateResult>("Record.Remove", content);
        }
    }
}
