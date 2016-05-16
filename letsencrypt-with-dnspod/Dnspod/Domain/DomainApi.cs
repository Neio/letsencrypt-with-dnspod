using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod.Dnspod.Domain
{
    public class DomainApi
    {
        private DnspodApi framework;


        public DomainApi(DnspodApi framework)
        {
            this.framework = framework;


        }

        public async Task<DnspodDomainListResult> List()
        {
            var args = framework.getArgs();
            var content = new FormUrlEncodedContent(args);
            return await DnspodApi.post<DnspodDomainListResult>("Domain.List", content);
        }


    }
}
