using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;
using WinsockPacketEditor;

// Test-only. Executes the supplied, unchanged .NET Framework assembly.
static class ConfigFileOracle
{
    static void Save(string file,XElement root){new XDocument(new XDeclaration("1.0","utf-8","yes"),root).Save(file);}
    public static int Run(string input,string output)
    {
        Directory.CreateDirectory(output);
        var db=Path.Combine(output,"db");Directory.CreateDirectory(db);
        if(File.Exists(Path.Combine(db,"oracle.db")))throw new Exception("Fresh oracle directory required");
        Operate.DataBase.dbPath=db;Operate.DataBase.dbName="oracle.db";Operate.DataBase.InitDB();
        Operate.SystemConfig.LoadSystemConfig_FromDB();
        Operate.SystemConfig.LoadInjectMode_FromDB();
        Operate.SystemConfig.LoadProxyMode_FromDB();
        Operate.SystemConfig.SetSystemConfig_FromXML(XElement.Load(Path.Combine(input,"system.xml")));
        Operate.FilterConfig.List.LoadFilterList_FromXDocument(XDocument.Load(Path.Combine(input,"input.fp")));
        Operate.SendConfig.List.LoadSendList_FromXDocument(XDocument.Load(Path.Combine(input,"input.sp")));
        Operate.RobotConfig.List.LoadRobotList_FromXDocument(XDocument.Load(Path.Combine(input,"input.rp")));
        Operate.WareHouseConfig.List.LoadWareHouseList_FromXDocument(XDocument.Load(Path.Combine(input,"input.whp")));
        var roots=new[]{Operate.FilterConfig.List.GetFilterList_XML(Operate.FilterConfig.List.lstFilterInfo.ToList()),
            Operate.SendConfig.List.GetSendList_XML(Operate.SendConfig.List.lstSendInfo.ToList()),
            Operate.RobotConfig.List.GetRobotList_XML(Operate.RobotConfig.List.lstRobotInfo.ToList()),
            Operate.WareHouseConfig.List.GetWareHouseList_XML(Operate.WareHouseConfig.List.lstWareHouseInfo.ToList())};
        var kinds=new[]{"fp","sp","rp","whp"};
        for(int i=0;i<4;i++)Save(Path.Combine(output,"original."+kinds[i]),roots[i]);
        // XElement.Value turns a null/self-closing text field into an empty
        // string on import. Capture both states, rather than expect a false
        // byte-identical roundtrip of an upstream default-null configuration.
        var system=Operate.SystemConfig.GetSystemConfig_XML();Save(Path.Combine(output,"system-before-import.xml"),system);
        Operate.SystemConfig.SetSystemConfig_FromXML(system);
        system=Operate.SystemConfig.GetSystemConfig_XML();Save(Path.Combine(output,"system.xml"),system);
        Save(Path.Combine(output,"original.sb"),new XElement("WPE64_BackUp",system,roots));
        var inject=new XElement("InjectMode",
            new XElement("HookWS1_Send",false),new XElement("HookWS1_SendTo",true),new XElement("HookWS1_Recv",false),new XElement("HookWS1_RecvFrom",true),
            new XElement("HookWS2_Send",true),new XElement("HookWS2_SendTo",false),new XElement("HookWS2_Recv",true),new XElement("HookWS2_RecvFrom",false),
            new XElement("HookWSA_Send",false),new XElement("HookWSA_SendTo",false),new XElement("HookWSA_Recv",true),new XElement("HookWSA_RecvFrom",true),
            new XElement("PacketList_AutoRoll",true),new XElement("PacketList_AutoClear",false),new XElement("PacketList_AutoClear_Value",12345));
        var proxy=new XElement("ProxyMode",
            new XElement("ProxyIP_Auto",false),new XElement("Enable_SOCKS5",true),new XElement("Enable_HTTP",true),new XElement("ProxyIP","127.0.0.1"),
            new XElement("SOCKS5_Port",1088),new XElement("HTTP_Port",8088),new XElement("Enable_Auth",false),new XElement("MaxConnectionNumber",4321),
            new XElement("Enable_UnPack",true),new XElement("UnPack_Head","AA BB"),new XElement("UnPack_Length","2-3"),new XElement("Enable_MapLocal",true),
            new XElement("Enable_MapRemote",false),new XElement("Enable_ExternalProxy",true),new XElement("ExternalProxy_IP","2001:db8::1"),new XElement("ExternalProxy_Port",65535),
            new XElement("Enable_ExternalProxy_AppointPort",true),new XElement("ExternalProxy_AppointPort","80,443"),new XElement("Enable_ExternalProxy_Auth",true),
            new XElement("ExternalProxy_UserName","用户<&>"),new XElement("ExternalProxy_PassWord","p\"'&"),new XElement("MustTCP",false),new XElement("MustTCP_IP",string.Empty),
            new XElement("MustTCP_Port",1),new XElement("MustTCP_Auth",true),new XElement("MustTCP_UserName","u"),new XElement("MustTCP_PassWord","p"),
            new XElement("MustTCP_AppointPort",true),new XElement("MustTCP_AppointPortContent","1-10"),new XElement("EnableFireWall",true),new XElement("Only_WPC_Client",false),
            new XElement("WhiteListMode",true),new XElement("FireWall_AutoWhiteList_AuthSuccess",true),new XElement("FireWall_AutoBlackList_UnSupport",false),
            new XElement("FireWall_AutoBlackList_AuthFail",true),new XElement("FireWall_AutoBlackList_Minutes",1440),new XElement("FireWall_AutoClear_Expiry",true),
            new XElement("DriverType",2),new XElement("SelectProcessNames","a.exe\nb.exe"));
        Operate.SystemConfig.SetInjectMode_FromXML(inject);Operate.SystemConfig.SetProxyMode_FromXML(proxy);
        inject=Operate.SystemConfig.GetInjectMode_XML();proxy=Operate.SystemConfig.GetProxyMode_XML();
        Save(Path.Combine(output,"inject.xml"),inject);Save(Path.Combine(output,"proxy.xml"),proxy);
        Save(Path.Combine(output,"settings.sb"),new XElement("WPE64_BackUp",proxy,inject));
        var cases=new JArray();var passwords=new[]{"compatibility-test", "密码中文测试", "emoji-\U0001F512-\U0001F600", "\u00e9\u20ac\u0416\u3042\u3000", " leading and trailing ", "x", "\0embedded\0"};
        foreach(var kind in kinds.Concat(new[]{"sb"}))for(int i=0;i<passwords.Length;i++)
        {
            var file=Path.Combine(output,kind+"-"+i+".encrypted");File.Copy(Path.Combine(output,"original."+kind),file);
            Operate.SystemConfig.EncryptXMLFile(file,passwords[i]);
            var restored=Operate.SystemConfig.DecryptXMLFile(file,passwords[i]);if(restored==null)throw new Exception("Original encryption failed");
            cases.Add(new JObject { ["plain"]="original."+kind,["encrypted"]=Path.GetFileName(file),["password"]=passwords[i] });
        }
        string hash;using(var sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(typeof(Operate).Assembly.Location))).Replace("-","");
        File.WriteAllText(Path.Combine(output,"crypto.json"),new JObject { ["sourceAssemblySha256"]=hash,["codePage"]=Encoding.Default.CodePage,["cases"]=cases }.ToString());
        Console.WriteLine("PASS: original loaders and serializers, 4 parent lists + 5-section backup, "+cases.Count+" cipher vectors, ACP="+Encoding.Default.CodePage);return 0;
    }
    public static int Verify(string file,string password)
    {
        var doc=Operate.SystemConfig.DecryptXMLFile(file,password);if(doc==null||doc.Root==null)throw new Exception("Original rejected native encrypted XML");
        Console.WriteLine("PASS: unchanged original decrypted native "+doc.Root.Name);return 0;
    }
    public static int VerifySettingsDatabase(string database,string output)
    {
        var file=Path.GetFullPath(database);Operate.DataBase.dbPath=Path.GetDirectoryName(file);Operate.DataBase.dbName=Path.GetFileName(file);Operate.DataBase.InitConStr();
        Operate.SystemConfig.LoadProxyMode_FromDB();Operate.SystemConfig.LoadInjectMode_FromDB();
        Save(output,new XElement("WPE64_BackUp",Operate.SystemConfig.GetProxyMode_XML(),Operate.SystemConfig.GetInjectMode_XML()));
        Console.WriteLine("PASS: unchanged original loaded native ProxyMode and InjectMode database rows");return 0;
    }
}
