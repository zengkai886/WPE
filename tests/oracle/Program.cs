using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using WinsockPacketEditor.Ipc;

// Test-only executable. The two upstream codec files are copied byte-for-byte.
// No product UI, hook, certificate, proxy or database initialization is invoked.
internal static class Program
{
    private static readonly List<string> Rows = new List<string>();

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 2 && args[0] == "generate-ring") { RingOracle.Generate(args[1]); return 0; }
            if (args.Length == 2 && args[0] == "generate")
            {
                Generate();
                File.WriteAllLines(args[1], Rows, new UTF8Encoding(false));
                Console.WriteLine("Original C# oracle: " + Rows.Count + " vectors generated.");
                Console.WriteLine("Reference runtime: CLR " + Environment.Version + "; corelib " + typeof(object).Assembly.FullName);
                return 0;
            }
            if (args.Length == 3 && args[0] == "verify-native")
            {
                VerifyNative(args[1], args[2]);
                return 0;
            }
            Console.Error.WriteLine("generate <vectors.tsv> | verify-native <vectors.tsv> <native.tsv>");
            return 2;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    private static string Bytes(byte[] b) { return b == null ? "~" : Convert.ToBase64String(b); }
    private static byte[] Unbytes(string s) { return s == "~" ? null : Convert.FromBase64String(s); }
    private static string Text(string s)
    {
        if (s == null) return "~";
        var bytes = new byte[s.Length * 2];
        Buffer.BlockCopy(s.ToCharArray(), 0, bytes, 0, bytes.Length);
        return Bytes(bytes); // Raw UTF-16 code units preserve deliberately unpaired surrogates.
    }
    private static void Row(params object[] values)
    {
        Rows.Add(string.Join("\t", values.Select(v => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture))));
    }

    private static void Generate()
    {
        string[] texts = { null, "", "ASCII", "中文封包", "a\0b", "\ud83d\ude00", "a\ud800b", "\udc00", "\ud800\ud800" };
        int[] ints = { 0, 1, -1, int.MinValue, int.MaxValue, 0x12345678 };
        long[] longs = { 0, 1, -1, long.MinValue, long.MaxValue, 0x0123456789abcdefL, 638937792000000000L };
        Guid guid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
        for (int i = 0; i < 189; i++)
        {
            byte u = (byte)(i * 47);
            bool b = (i % 2) == 0;
            int n = ints[i % ints.Length];
            long l = longs[i % longs.Length];
            string t = texts[i % texts.Length];
            byte[] data = i % 3 == 0 ? null : Enumerable.Range(0, i % 65).Select(x => (byte)(x * 71)).ToArray();
            var w = new IpcWriter();
            w.U8(u); w.Bool(b); w.I32(n); w.I64(l); w.Str(t); w.Bytes(data); w.Guid_(guid);
            Row("primitive", "p" + i, u, b ? 1 : 0, n, l, Text(t), Bytes(data), guid.ToString(), Bytes(w.ToArray()));
        }
        for (int i = 0; i < 600; i++)
        {
            byte[] raw = i % 11 == 0 ? null : Enumerable.Range(0, i % 257).Select(x => (byte)(x + i)).ToArray();
            byte[] mod = i % 4 == 0 ? raw : i % 4 == 1 ? (raw == null ? null : raw.ToArray()) : i % 4 == 2 ? new byte[0] : new byte[] { 0, 128, 255, (byte)i };
            long id = longs[i % longs.Length], ticks = 638937792000000000L + i, socket = i % 2 == 0 ? 0xffffffffL : 0x7fffffffffffffffL;
            string from = texts[i % 6], to = i % 2 == 0 ? "127.0.0.1:1234" : "[::1]:65535";
            byte type = (byte)(i % 256), action = (byte)((i * 5) % 256);
            Row("packet", "k" + i, id, ticks, socket, type, action, Text(from), Text(to), Bytes(raw), Bytes(mod),
                Bytes(PacketFrame.Encode(id, ticks, socket, type, action, from, to, raw, mod)));
        }
        for (int i = 0; i < 37; i++)
        {
            byte[] data = Enumerable.Range(0, i * 113).Select(x => (byte)(x * 31)).ToArray();
            using (var s = new MemoryStream()) { IpcFrame.Write(s, data); Row("frame", "f" + i, Bytes(data), Bytes(s.ToArray())); }
        }
        byte[][] streams = {
            new byte[0], new byte[] { 1 }, new byte[] { 1,0,0 }, new byte[] {1,0,0,0},
            new byte[] {2,0,0,0,255}, new byte[] {0,0,0,0}, new byte[] {1,0,0,0,42},
            new byte[] {255,255,255,255}, new byte[] {0,0,0,128}, new byte[] {9,0,0,0},
            new byte[] {1,0,0,0,42,0,0,0,0}, new byte[] {1,0,0,0,42,0}
        };
        for (int i = 0; i < streams.Length; i++)
        {
            string result;
            using (var s = new OneByteStream(streams[i]))
            {
                var parts = new List<string>();
                for (int j = 0; j < 4; j++)
                {
                    try
                    {
                        byte[] data = IpcFrame.Read(s, 8);
                        parts.Add(data == null ? "EOF" : "OK:" + Bytes(data));
                        if (data == null) break;
                    }
                    catch (IOException) { parts.Add("IO"); break; }
                }
                result = string.Join(",", parts);
            }
            Row("read", "r" + i, Bytes(streams[i]), 8, result);
        }
        byte[][] utf8Cases = {
            new byte[]{0x80}, new byte[]{0xbf}, new byte[]{0xc0,0xaf}, new byte[]{0xc1,0xbf},
            new byte[]{0xc2}, new byte[]{0xc2,0x41}, new byte[]{0xc2,0xa2},
            new byte[]{0xe0}, new byte[]{0xe0,0x80,0x80}, new byte[]{0xe0,0xa0}, new byte[]{0xe0,0xa0,0x80},
            new byte[]{0xed,0xa0,0x80}, new byte[]{0xed,0xbf,0xbf}, new byte[]{0xed,0x9f,0xbf},
            new byte[]{0xe1,0x80,0x41}, new byte[]{0xf0,0x80,0x80,0x80}, new byte[]{0xf0,0x90,0x80},
            new byte[]{0xf0,0x90,0x80,0x80}, new byte[]{0xf4,0x90,0x80,0x80}, new byte[]{0xf4,0x8f,0xbf,0xbf},
            new byte[]{0xff,0xff}, new byte[]{0xf5,0x80,0x80,0x80}, new byte[]{0x61,0xed,0xa0,0x80,0x62}
        };
        for (int i=0; i<utf8Cases.Length; i++)
        {
            var w=new IpcWriter(); w.Bytes(utf8Cases[i]);
            byte[] payload=w.ToArray();
            Row("decode-string", "utf"+i, Bytes(payload), Text(new IpcReader(payload).Str()));
        }
        // Exhaust every two-byte input, then sample longer byte sequences with a fixed seed.
        for (int pair=0; pair<65536; pair++)
        {
            var w=new IpcWriter(); w.Bytes(new byte[]{(byte)(pair>>8),(byte)pair});
            byte[] payload=w.ToArray();
            Row("decode-string", "pair"+pair, Bytes(payload), Text(new IpcReader(payload).Str()));
        }
        var random=new Random(190917);
        for (int i=0; i<8192; i++)
        {
            byte[] data=new byte[3+i%6]; random.NextBytes(data);
            var w=new IpcWriter(); w.Bytes(data); byte[] payload=w.ToArray();
            Row("decode-string", "random-utf"+i, Bytes(payload), Text(new IpcReader(payload).Str()));
        }
        byte[] full = PacketFrame.Encode(7,8,9,1,2,"from","to",new byte[]{1,2,3},new byte[]{4,5});
        for (int i=0; i<full.Length; i++)
        {
            byte[] partial=full.Take(i).ToArray(); string result;
            try { PacketFrame.Decode(partial); result="OK"; }
            catch(IOException) { result="IO"; }
            Row("decode-packet", "truncated"+i, Bytes(partial),result);
        }
        Type[] enums = { typeof(IpcCommand), typeof(IpcEvent), typeof(ConfigKind), typeof(IpcStatus), typeof(ResetWhat) };
        foreach (Type e in enums)
            foreach (string name in Enum.GetNames(e))
                Row("enum", e.Name + "." + name, e.Name, name, Convert.ToInt32(Enum.Parse(e,name)));
        Row("constant", "version", "version", IpcProtocol.Version);
        Row("constant", "max-control", "max-control", IpcProtocol.MaxControlFrame);
        Row("constant", "max-packet", "max-packet", IpcProtocol.MaxPacketFrame);
        string session = "00112233445566778899aabbccddeeff";
        Row("pipe", "control", session, IpcProtocol.ControlPipe(session));
        Row("pipe", "packet", session, IpcProtocol.PacketPipe(session));
        Row("pipe", "event", session, IpcProtocol.EventPipe(session));
    }

    private static void VerifyNative(string fixtures, string nativeOutput)
    {
        var expected = File.ReadAllLines(fixtures).Select(x => x.Split('\t')).Where(x => x[0] == "packet").ToDictionary(x => x[1]);
        var seen = new HashSet<string>();
        foreach (string line in File.ReadAllLines(nativeOutput))
        {
            string[] fields = line.Split('\t');
            if (fields.Length != 2 || !seen.Add(fields[0])) throw new Exception("Invalid/duplicate native result");
            var original = expected[fields[0]];
            byte[] actual = Unbytes(fields[1]), bytes = Unbytes(original[original.Length - 1]);
            if (!actual.SequenceEqual(bytes)) throw new Exception("Wire mismatch " + fields[0]);
            var a = PacketFrame.Decode(actual); var b = PacketFrame.Decode(bytes);
            if (a.Id != b.Id || a.TimeTicks != b.TimeTicks || a.Socket != b.Socket || a.PacketType != b.PacketType || a.FilterAction != b.FilterAction || a.From != b.From || a.To != b.To || !Equal(a.Raw,b.Raw) || !Equal(a.Modified,b.Modified))
                throw new Exception("Decode mismatch " + fields[0]);
        }
        if (seen.Count != expected.Count) throw new Exception("Missing native output rows");
        Console.WriteLine("Original C# decoder accepted " + seen.Count + " native packet frames; all bytes and decoded fields match.");
    }
    private static bool Equal(byte[] a, byte[] b) { return a == null ? b == null : b != null && a.SequenceEqual(b); }
    private sealed class OneByteStream : MemoryStream
    {
        public OneByteStream(byte[] data) : base(data) { }
        public override int Read(byte[] buffer, int offset, int count) { return base.Read(buffer, offset, Math.Min(count,1)); }
    }
}

