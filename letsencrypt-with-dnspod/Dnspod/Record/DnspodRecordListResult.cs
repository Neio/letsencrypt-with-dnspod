using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod.Dnspod.Record
{
    public class DnspodRecordListResult : DnspodResult
    {
        public DnspodRecordListResultDomainItem domain { get; set; }
        public DnspodRecordListResultInfoItem info { get; set; }
        public DnspodRecordListResultRecordItem[] records { get; set; }
    }

    public class DnspodRecordListResultDomainItem
    {
        public int id { get; set; }
        public string name { get; set; }
        public string punycode { get; set; }
        public string grade { get; set; }
        public string owner { get; set; }
    }

    public class DnspodRecordListResultInfoItem
    {
        public int sub_domains { get; set; }
        public int record_total { get; set; }
    }

    public class DnspodRecordListResultRecordItem
    {
        public int id { get; set; }
        public string name { get; set; }
        public string line { get; set; }
        public string type { get; set; }
        public int ttl { get; set; }
        public string value { get; set; }
        public string mx { get; set; }
        public string enabled { get; set; }
        public string status { get; set; }
        public string monitor_status { get; set; }
        public string remark { get; set; }
        public DateTime updated_on { get; set; }
        public string use_aqb { get; set; }
        public string hold { get; set; }
    }

}
