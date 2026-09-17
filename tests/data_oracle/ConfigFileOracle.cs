using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
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
        var white=new BindingList<WhiteListInfo> {
            new WhiteListInfo("192.168.1.10","局域网",false,Operate.SystemConfig.MaxDateTime,new DateTime(2026,9,18,1,2,3)),
            new WhiteListInfo("10.0.0.1-10.0.0.25","局域网",true,new DateTime(2027,1,2,3,4,5),new DateTime(2026,9,18,2,3,4)) };
        var black=new BindingList<BlackListInfo> {
            new BlackListInfo("203.0.113.7","测试网络",true,new DateTime(2026,12,31,23,59,58),new DateTime(2026,9,18,3,4,5)),
            new BlackListInfo("198.51.100.1-198.51.100.200","测试网络",false,Operate.SystemConfig.MaxDateTime,new DateTime(2026,9,18,4,5,6)) };
        var whiteXml=Operate.ProxyConfig.Proxy.GetWhiteList_XML(white);var blackXml=Operate.ProxyConfig.Proxy.GetBlackList_XML(black);
        Save(Path.Combine(output,"original.wl"),whiteXml);Save(Path.Combine(output,"original.bl"),blackXml);
        Save(Path.Combine(output,"ip-rules.sb"),new XElement("WPE64_BackUp",whiteXml,blackXml));
        Save(Path.Combine(output,"supported-nine.sb"),new XElement("WPE64_BackUp",system,proxy,whiteXml,blackXml,inject,roots));
        var accounts=new List<AccountInfo> {
            new AccountInfo(new Guid("55555555-5555-5555-5555-555555555555"),true,"alice<&>",Operate.SystemConfig.PassWord_Encrypt("P@ss'中"),new BindingList<AccountIPInfo> {
                new AccountIPInfo(new DateTime(2026,9,18,5,6,7),"192.0.2.10","测试网络"),new AccountIPInfo(new DateTime(2026,9,18,6,7,8),"198.51.100.20","测试网络") },true,7,false,0,true,new DateTime(2027,2,3,4,5,6),new DateTime(2026,9,18,4,3,2)),
            new AccountInfo(new Guid("66666666-6666-6666-6666-666666666666"),false,"用户二",Operate.SystemConfig.PassWord_Encrypt("!Zz 905"),new BindingList<AccountIPInfo>(),false,0,true,2,false,Operate.SystemConfig.MaxDateTime,new DateTime(2026,9,18,7,8,9)) };
        var accountXml=Operate.ProxyConfig.Account.GetAccountList_XML(accounts);Save(Path.Combine(output,"original.pa"),accountXml);
        Save(Path.Combine(output,"accounts.sb"),new XElement("WPE64_BackUp",accountXml));
        Save(Path.Combine(output,"supported-ten.sb"),new XElement("WPE64_BackUp",system,proxy,accountXml,whiteXml,blackXml,inject,roots));
        var batchAccounts=new BindingList<AccountInfo> {
            new AccountInfo { UserName="batch-001",Password=Operate.SystemConfig.PassWord_Encrypt("Az09!?"),ExpiryTime=new DateTime(2030,1,2,3,4,5) },
            new AccountInfo { UserName="批量用户002",Password=Operate.SystemConfig.PassWord_Encrypt("密码二"),ExpiryTime=new DateTime(2030,1,2,3,4,5) } };
        var batchWriter=typeof(Operate.ProxyConfig.Account).GetMethod("SaveBatchAccountsToExcel",BindingFlags.Static|BindingFlags.NonPublic);
        if(batchWriter==null||!(bool)batchWriter.Invoke(null,new object[]{Path.Combine(output,"batch-accounts.xls"),batchAccounts}))throw new Exception("Original batch account export failed");
        var cases=new JArray();var passwords=new[]{"compatibility-test", "密码中文测试", "emoji-\U0001F512-\U0001F600", "\u00e9\u20ac\u0416\u3042\u3000", " leading and trailing ", "x", "\0embedded\0"};
        foreach(var kind in kinds.Concat(new[]{"wl","bl","pa","sb"}))for(int i=0;i<passwords.Length;i++)
        {
            var file=Path.Combine(output,kind+"-"+i+".encrypted");File.Copy(Path.Combine(output,"original."+kind),file);
            Operate.SystemConfig.EncryptXMLFile(file,passwords[i]);
            var restored=Operate.SystemConfig.DecryptXMLFile(file,passwords[i]);if(restored==null)throw new Exception("Original encryption failed");
            cases.Add(new JObject { ["plain"]="original."+kind,["encrypted"]=Path.GetFileName(file),["password"]=passwords[i] });
        }
        string hash;using(var sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(typeof(Operate).Assembly.Location))).Replace("-","");
        File.WriteAllText(Path.Combine(output,"crypto.json"),new JObject { ["sourceAssemblySha256"]=hash,["codePage"]=Encoding.Default.CodePage,["cases"]=cases }.ToString());
        Console.WriteLine("PASS: original loaders and serializers, 4 parent lists + settings/IP/account backups, "+cases.Count+" cipher vectors, ACP="+Encoding.Default.CodePage);return 0;
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
    public static int VerifyIpRulesDatabase(string database,string output)
    {
        var file=Path.GetFullPath(database);Operate.DataBase.dbPath=Path.GetDirectoryName(file);Operate.DataBase.dbName=Path.GetFileName(file);Operate.DataBase.InitConStr();
        int whiteCount=Operate.DataBase.SelectTable_WhiteList().Rows.Count,blackCount=Operate.DataBase.SelectTable_BlackList().Rows.Count;
        Operate.ProxyConfig.Proxy.LoadWhiteList_FromDB();Operate.ProxyConfig.Proxy.LoadBlackList_FromDB();
        if(!SpinWait.SpinUntil(()=>Operate.ProxyConfig.Proxy.lstWhiteList.Count==whiteCount&&Operate.ProxyConfig.Proxy.lstBlackList.Count==blackCount,5000))throw new Exception("Original IP-rule loaders did not settle");
        Save(output,new XElement("WPE64_BackUp",Operate.ProxyConfig.Proxy.GetWhiteList_XML(Operate.ProxyConfig.Proxy.lstWhiteList),Operate.ProxyConfig.Proxy.GetBlackList_XML(Operate.ProxyConfig.Proxy.lstBlackList)));
        Console.WriteLine("PASS: unchanged original loaded native WhiteList and BlackList database rows");return 0;
    }
    public static int VerifyAccountsDatabase(string database,string output)
    {
        var file=Path.GetFullPath(database);Operate.DataBase.dbPath=Path.GetDirectoryName(file);Operate.DataBase.dbName=Path.GetFileName(file);Operate.DataBase.InitConStr();
        int accountCount=Operate.DataBase.SelectTable_ProxyAccount().Rows.Count,loginCount=Operate.DataBase.SelectTable_ProxyAccountIPInfo().Rows.Count;Operate.ProxyConfig.Account.LoadProxyAccountList_FromDB();
        if(!SpinWait.SpinUntil(()=>Operate.ProxyConfig.Account.lstAccountInfo.Count==accountCount&&Operate.ProxyConfig.Account.lstAccountInfo.Sum(x=>x.AIPInfo.Count)==loginCount,5000))throw new Exception("Original account loader did not settle");
        Save(output,Operate.ProxyConfig.Account.GetAccountList_XML(Operate.ProxyConfig.Account.lstAccountInfo.ToList()));Console.WriteLine("PASS: unchanged original loaded native ProxyAccount and ProxyAccountIPInfo rows");return 0;
    }
}
