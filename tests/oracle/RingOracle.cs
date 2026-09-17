using System;
using System.IO;
using System.Linq;
using System.Text;
using WinsockPacketEditor.Ipc;

// Only type declarations required to compile unchanged PacketRing.cs in isolation.
// None of the original business program is started by this oracle.
namespace WinsockPacketEditor {
    public static class Operate {
        public static class PacketConfig { public static class Packet {
            public enum PacketType { None }
            public struct SockAddr { }
        } }
        public static class FilterConfig { public static class Filter { public enum FilterAction { None } } }
    }
}
internal static class RingOracle {
    private static PendingPacket Packet(long id, int rawLength, int mode, int modifiedLength) {
        var raw = rawLength < 0 ? null : new byte[rawLength];
        var modified = mode == 0 ? null : mode == 1 ? raw : modifiedLength < 0 ? null : new byte[modifiedLength];
        return new PendingPacket { Id=id, Raw=raw, Modified=modified };
    }
    public static void Generate(string path) {
        int rows=0;
        using(var writer=new StreamWriter(path,false,new UTF8Encoding(false))) {
            var random=new Random(64917);
            int[] counts={0,1,8,64}; long[] sizes={0,128,512,4096}; int[] lengths={-1,0,1,32,1000};
            for(int scenario=0;scenario<16;scenario++) {
                int cap=counts[scenario%4]; long bytes=sizes[scenario/4];
                var ring=new PacketRing(cap,bytes);
                writer.WriteLine("new\t"+cap+"\t"+bytes); rows++;
                for(int step=0;step<400;step++) {
                    int action=random.Next(10);
                    if(action<6) {
                        int raw=lengths[random.Next(lengths.Length)], mode=random.Next(3), mod=lengths[random.Next(lengths.Length)];
                        long id=scenario*1000L+step;
                        var item=Packet(id,raw,mode,mod); ring.Enqueue(item);
                        writer.WriteLine(string.Join("\t","enqueue",id,raw,mode,mod,item.Size,ring.Count,ring.Dropped));
                    } else if(action<9) {
                        int take=random.Next(0,10); long limit=sizes[random.Next(sizes.Length)];
                        var batch=ring.DequeueBatch(take,limit,0);
                        writer.WriteLine(string.Join("\t","take",take,limit,string.Join(",",batch.Select(x=>x.Id)),ring.Count,ring.Dropped));
                    } else {
                        ring.Clear(); writer.WriteLine(string.Join("\t","clear",ring.Count,ring.Dropped));
                    }
                    rows++;
                }
            }
        }
        Console.WriteLine("Original C# PacketRing: "+rows+" state-transition vectors generated.");
    }
}
