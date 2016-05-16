using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod.Dnspod.Domain
{
    public class DnspodDomainListResult : DnspodResult
    {
        public Info info { get; set; }
        public Domain[] domains { get; set; }
    }

    public class Info
    {
        public int domain_total { get; set; }
        public int all_total { get; set; }
        public int mine_total { get; set; }
        public int share_total { get; set; }
        public int vip_total { get; set; }
        public int ismark_total { get; set; }
        public int pause_total { get; set; }
        public int error_total { get; set; }
        public int lock_total { get; set; }
        public int spam_total { get; set; }
        public int vip_expire { get; set; }
        public int share_out_total { get; set; }
    }

    public class Domain
    {
        public int id { get; set; }
        public string status { get; set; }
        public string grade { get; set; }
        public string group_id { get; set; }
        public string searchengine_push { get; set; }
        public string is_mark { get; set; }
        public int ttl { get; set; }
        public string cname_speedup { get; set; }
        public string remark { get; set; }
        public DateTime created_on { get; set; }
        public string updated_on { get; set; }
        public string punycode { get; set; }
        public string ext_status { get; set; }
        public string name { get; set; }
        public string grade_title { get; set; }
        public string is_vip { get; set; }
        public string owner { get; set; }
        public int records { get; set; }
        public bool auth_to_anquanbao { get; set; }

        public override string ToString()
        {
            return name;
        }
    }
}
