using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod
{
    class Target
    {
        public string Host { get; set; }
        public List<string> AlternativeNames { get; set; }

        public override string ToString() => $"{Host}";
    }
}
