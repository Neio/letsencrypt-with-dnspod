using io.nulldata.letsencrypt_with_dnspod.Dnspod;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace io.nulldata.letsencrypt_with_dnspod
{
    class Program
    {
        static void Main(string[] args)
        {
            var api = new DnspodApi();
            var ls = api.Domain.List().Result;
            foreach (var domain in ls.domains)
            {
                Console.WriteLine(domain.name);
            }
            var d = ls.domains[0];
            var rc = api.Record.Create(d.id, "hello", "hello").Result;
            Console.WriteLine();
            var rm = api.Record.Modify(d.id, rc.record.id, "hello", "hello_hello").Result;
            Console.WriteLine();
            var rd = api.Record.Remove(d.id, rc.record.id).Result;
            Console.WriteLine();
        }
    }
}
