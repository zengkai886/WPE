using System;
using System.IO;
using System.ComponentModel;
using System.Linq;
using WinsockPacketEditor;

// Unchanged original loaders and serializers, not a reimplementation of XML.
static class ExportOracle
{
    public static int Run(string fixtures,string output)
    {
        Directory.CreateDirectory(output);
        var packets=new BindingList<PacketInfo>();var stores=new BindingList<DataInfo>();
        if(!Operate.SendConfig.Send.LoadSendCollection(Path.Combine(fixtures,"editor-send.sc"),packets,false).GetAwaiter().GetResult())throw new Exception("Original send import failed");
        if(!Operate.WareHouseConfig.List.LoadStores(Path.Combine(fixtures,"editor-stores.whs"),stores,false).GetAwaiter().GetResult())throw new Exception("Original stores import failed");
        Operate.SendConfig.Send.SaveSendCollection(Path.Combine(output,"export-original.sc"),packets.ToList(),false,"");
        Operate.WareHouseConfig.List.SaveStores(Path.Combine(output,"export-original.whs"),stores.ToList(),false,"");
        Console.WriteLine("PASS: unchanged original serializers exported "+packets.Count+" packets and "+stores.Count+" stores");return 0;
    }
    public static int Verify(string file,string output)
    {
        if(Path.GetExtension(file).Equals(".sc",StringComparison.OrdinalIgnoreCase)){
            var rows=new BindingList<PacketInfo>();if(!Operate.SendConfig.Send.LoadSendCollection(file,rows,false).GetAwaiter().GetResult())throw new Exception("Original loader rejected native send export");
            Operate.SendConfig.Send.SaveSendCollection(output,rows.ToList(),false,"");Console.WriteLine("Original loader read "+rows.Count+" native send packets");
        }else{
            var rows=new BindingList<DataInfo>();if(!Operate.WareHouseConfig.List.LoadStores(file,rows,false).GetAwaiter().GetResult())throw new Exception("Original loader rejected native stores export");
            Operate.WareHouseConfig.List.SaveStores(output,rows.ToList(),false,"");Console.WriteLine("Original loader read "+rows.Count+" native store entries");
        }
        if(!File.ReadAllBytes(file).SequenceEqual(File.ReadAllBytes(output)))throw new Exception("Native file differs from original loader/serializer roundtrip");
        Console.WriteLine("PASS: native file -> original loader -> original serializer, byte-for-byte equality");return 0;
    }
}
