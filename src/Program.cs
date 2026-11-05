// The official doh listener package's server process (ADR-025 in the Rod
// platform repository): a per-peer byte pipe between its DNS faces and the
// kernel's bridge.
//
// Two faces, one grammar: the RFC 8484 HTTPS face (GET with the
// urlsafe-base64 dns parameter, POST with an application/dns-message body)
// and the classic UDP face. Every query -- HTTP body or datagram -- crosses
// to the kernel as one route-forward unit (POST /dns-query, the body the
// DNS wire message) and the kernel answers with the same DnsContactAnswerer
// core the in-tree UDP listener and DoH route drive. The process parses no
// rod.v1 grammar, holds no engagement key, and learns no implant identity;
// the carriage changes, the answer never does.
//
// The DoH face is always TLS: the leaf arrives as a user-only PEM the
// kernel hands over (ROD_LISTENER_TLS_PEM), the engagement CA's server
// leaf, and the front never serves cleartext.
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

var socket = Environment.GetEnvironmentVariable("ROD_BRIDGE_SOCKET");
if (args.Length == 1 && args[0] == "--selftest")
    return Self.Run();
if (string.IsNullOrEmpty(socket))
{
    Console.Error.WriteLine("rod-listener-doh: ROD_BRIDGE_SOCKET is not set; the supervisor spawns this process.");
    return 1;
}

var parameters = System.Text.Json.JsonSerializer.Deserialize(
    Environment.GetEnvironmentVariable("ROD_LISTENER_PARAMS") ?? "{}",
    Self.ParamsContext.Default.Params) ?? new Self.Params();
var udpBind = parameters.UdpBind;
var httpBind = parameters.HttpBind;
var tlsPem = Environment.GetEnvironmentVariable("ROD_LISTENER_TLS_PEM");
if (string.IsNullOrEmpty(udpBind) && string.IsNullOrEmpty(httpBind))
{
    Console.Error.WriteLine("rod-listener-doh: neither udp-bind nor http-bind is set; a listener needs a face.");
    return 1;
}
if (!string.IsNullOrEmpty(httpBind) && string.IsNullOrEmpty(tlsPem))
{
    Console.Error.WriteLine("rod-listener-doh: the DoH face is always TLS, and no leaf arrived (ROD_LISTENER_TLS_PEM).");
    return 1;
}

var builder = WebApplication.CreateBuilder();
if (!string.IsNullOrEmpty(httpBind))
{
    var leaf = X509Certificate2.CreateFromPemFile(tlsPem!, tlsPem!);
    var bindAddress = Self.ParseBind(httpBind);
    builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(
        bindAddress.Address,
        bindAddress.Port,
        listen => listen.UseHttps(leaf)));
}
else
{
    // The UDP-only face still runs the web host for its lifetime plumbing;
    // park Kestrel on an anonymous loopback port so nothing else opens.
    builder.WebHost.UseUrls("http://127.0.0.1:0");
}

var app = builder.Build();

// The RFC 8484 GET: the urlsafe-base64 query under the dns parameter. The
// parameter decodes here -- the kernel's arm speaks wire bytes only.
app.MapGet("/dns-query", async (HttpRequest request, CancellationToken cancellation) =>
{
    var encoded = request.Query["dns"].ToString();
    if (encoded.Length == 0)
        return Results.BadRequest(new { error = "The dns parameter is required." });
    byte[] query;
    try
    {
        query = Convert.FromBase64String(Self.PadBase64(encoded.Replace('-', '+').Replace('_', '/')));
    }
    catch (FormatException)
    {
        return Results.BadRequest(new { error = "The dns parameter is not base64." });
    }
    return await Self.AnswerAsync(socket!, query, cancellation);
});

// The RFC 8484 POST: the wire message as the body, media type advisory
// (resolvers vary; the bytes decide).
app.MapPost("/dns-query", async (HttpRequest request, CancellationToken cancellation) =>
{
    using var body = new MemoryStream();
    await request.Body.CopyToAsync(body, cancellation);
    return await Self.AnswerAsync(socket!, body.ToArray(), cancellation);
});

if (!string.IsNullOrEmpty(udpBind))
{
    var bindAddress = Self.ParseBind(udpBind);
    await app.StartAsync();
    _ = Self.ServeUdpAsync(bindAddress, socket!, app.Lifetime.ApplicationStopping);
    Console.Error.WriteLine($"rod-listener-doh: udp face on {udpBind}, bridge {socket}");
    await app.WaitForShutdownAsync();
    return 0;
}

Console.Error.WriteLine($"rod-listener-doh: doh face on {httpBind}, bridge {socket}");
await app.RunAsync();
return 0;

// The package's non-host half, static so the self-test reaches it without
// a web host.
internal static partial class Self
{
    public sealed class Params
    {
        // The manifest's config-schema rows are kebab-case; the source
        // generator's default camelCase would never match them.
        [System.Text.Json.Serialization.JsonPropertyName("udp-bind")]
        public string? UdpBind { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("http-bind")]
        public string? HttpBind { get; set; }
    }

    [System.Text.Json.Serialization.JsonSerializable(typeof(Params))]
    public partial class ParamsContext : System.Text.Json.Serialization.JsonSerializerContext;

    public static IResult Ok(byte[] response)
        => Results.Bytes(response, "application/dns-message");

    public static async Task<IResult> AnswerAsync(string socket, byte[] query, CancellationToken cancellation)
    {
        try
        {
            var (status, _, body) = await ExchangeAsync(socket, "POST", "/dns-query", query, cancellation);
            return status == 200
                ? Ok(body)
                : Results.BadRequest(new { error = "The kernel refused the query." });
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        }
    }

    // --- The bridge's route-forward carriage (docs/extending/listeners.md).

    private const byte RouteCarriage = (byte)'R';
    private const int MaxFields = 64;

    public static async Task<(int Status, string ContentType, byte[] Body)> ExchangeAsync(
        string socketName, string method, string path, byte[] body, CancellationToken cancellation)
    {
        using var conn = await DialAsync(socketName, cancellation);
        await conn.WriteAsync(new byte[] { RouteCarriage }, cancellation);
        await WriteMessageAsync(conn, EncodeUnit(
            ("method", Encoding.UTF8.GetBytes(method)),
            ("path", Encoding.UTF8.GetBytes(path)),
            ("body", body)), cancellation);

        var wire = await ReadMessageAsync(conn, cancellation);
        var fields = DecodeUnit(wire);
        var status = 0;
        var contentType = "";
        var answer = Array.Empty<byte>();
        if (fields.TryGetValue("status", out var statusBytes))
        {
            var text = Encoding.ASCII.GetString(statusBytes);
            if (!int.TryParse(text, out status))
                throw new IOException("the answer's status is not a number");
        }
        if (fields.TryGetValue("content-type", out var contentTypeBytes))
            contentType = Encoding.UTF8.GetString(contentTypeBytes);
        if (fields.TryGetValue("body", out var bodyBytes))
            answer = bodyBytes;
        if (status == 0)
            throw new IOException("the answer carries no status");
        return (status, contentType, answer);
    }

    public static Task<Stream> DialAsync(string name, CancellationToken cancellation)
        => name.StartsWith(@"\\.\pipe\", StringComparison.Ordinal)
            ? DialPipe(name[@"\\.\pipe\".Length..], cancellation)
            : DialUnix(name, cancellation);

    private static async Task<Stream> DialPipe(string name, CancellationToken cancellation)
    {
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, cancellation);
        return pipe;
    }

    private static async Task<Stream> DialUnix(string path, CancellationToken cancellation)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellation);
        return new NetworkStream(socket, ownsSocket: true);
    }

    public static byte[] EncodeUnit(params (string Key, byte[] Value)[] fields)
    {
        var buffer = new MemoryStream();
        WriteVarint(buffer, (ulong)fields.Length);
        foreach (var (key, value) in fields)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            WriteVarint(buffer, (ulong)keyBytes.Length);
            buffer.Write(keyBytes);
            WriteVarint(buffer, (ulong)value.Length);
            buffer.Write(value);
        }
        return buffer.ToArray();
    }

    public static Dictionary<string, byte[]> DecodeUnit(byte[] message)
    {
        var offset = 0;
        if (!TryReadVarint(message, ref offset, out var count) || count > (ulong)MaxFields)
            throw new IOException("malformed route-forward unit");
        var fields = new Dictionary<string, byte[]>();
        for (var i = 0; i < (int)count; i++)
        {
            if (!TryReadBytes(message, ref offset, out var keyBytes)
                || !TryReadBytes(message, ref offset, out var value))
                throw new IOException("malformed route-forward unit");
            fields[Encoding.UTF8.GetString(keyBytes)] = value;
        }
        return fields;
    }

    public static async Task WriteMessageAsync(Stream stream, byte[] message, CancellationToken cancellation)
    {
        var prefix = new MemoryStream();
        WriteVarint(prefix, (ulong)message.Length);
        await stream.WriteAsync(prefix.ToArray(), cancellation);
        await stream.WriteAsync(message, cancellation);
    }

    public static async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellation)
    {
        ulong length = 0;
        var shift = 0;
        while (true)
        {
            var one = new byte[1];
            if (await stream.ReadAsync(one, cancellation) != 1)
                throw new EndOfStreamException();
            length |= (ulong)(one[0] & 0x7f) << shift;
            if ((one[0] & 0x80) == 0)
                break;
            shift += 7;
            if (shift > 28)
                throw new IOException("malformed message length");
        }
        var message = new byte[length];
        var read = 0;
        while (read < message.Length)
        {
            var took = await stream.ReadAsync(message.AsMemory(read), cancellation);
            if (took == 0)
                throw new EndOfStreamException();
            read += took;
        }
        return message;
    }

    // --- The UDP face: one datagram, one exchange, one datagram back.

    public static async Task ServeUdpAsync(IPEndPoint bind, string socket, CancellationToken stopping)
    {
        using var udp = new UdpClient(bind);
        while (!stopping.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await udp.ReceiveAsync(stopping);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    var (_, _, answer) = await ExchangeAsync(socket, "POST", "/dns-query", received.Buffer, stopping);
                    await udp.SendAsync(answer, answer.Length, received.RemoteEndPoint);
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
                {
                    // One datagram the kernel could not answer: dropped, the
                    // resolver's own retry discipline answers it.
                }
            }, stopping);
        }
    }

    public static IPEndPoint ParseBind(string bind)
    {
        var host = bind[..bind.LastIndexOf(':')];
        var port = int.Parse(bind[(bind.LastIndexOf(':') + 1)..]);
        return new IPEndPoint(host == "*" || host == "+" ? IPAddress.Any : IPAddress.Parse(host), port);
    }

    public static string PadBase64(string value)
        => value.Length % 4 == 0 ? value : value + new string('=', 4 - value.Length % 4);

    private static void WriteVarint(MemoryStream buffer, ulong value)
    {
        while (value >= 0x80)
        {
            buffer.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        buffer.WriteByte((byte)value);
    }

    private static void WriteVarintTo(List<byte> into, ulong value)
    {
        while (value >= 0x80)
        {
            into.Add((byte)(value | 0x80));
            value >>= 7;
        }
        into.Add((byte)value);
    }

    private static bool TryReadVarint(byte[] message, ref int offset, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (true)
        {
            if (offset >= message.Length || shift > 28)
                return false;
            var read = message[offset++];
            value |= (ulong)(read & 0x7f) << shift;
            if ((read & 0x80) == 0)
                return true;
            shift += 7;
        }
    }

    private static bool TryReadBytes(byte[] message, ref int offset, out byte[] value)
    {
        value = [];
        if (!TryReadVarint(message, ref offset, out var length) || length > (ulong)(message.Length - offset))
            return false;
        value = message[offset..(offset + (int)length)];
        offset += (int)length;
        return true;
    }

    // --- The self-test: the codec's wire form against the kernel's own
    // bytes, run by build.sh so a publish never rides an unverified codec.

    public static int Run()
    {
        var failures = 0;
        void Check(bool ok, string what)
        {
            if (!ok)
            {
                Console.Error.WriteLine($"selftest: {what} FAILED");
                failures++;
            }
        }

        var wire = EncodeUnit(
            ("method", Encoding.UTF8.GetBytes("GET")),
            ("path", Encoding.UTF8.GetBytes("/")));
        byte[] want =
        [
            0x02,
            0x06, .. Encoding.UTF8.GetBytes("method"),
            0x03, .. Encoding.UTF8.GetBytes("GET"),
            0x04, .. Encoding.UTF8.GetBytes("path"),
            0x01, (byte)'/',
        ];
        Check(wire.SequenceEqual(want), "the unit wire form");

        var decoded = DecodeUnit(wire);
        Check(decoded["method"].SequenceEqual("GET"u8.ToArray()), "the unit round trip");

        var oversized = new byte[17];
        oversized[0] = 0x7f;
        try
        {
            _ = DecodeUnit(oversized);
            Check(false, "the malformed-unit refusal");
        }
        catch (IOException)
        {
        }

        Console.WriteLine(failures == 0 ? "selftest: ok" : $"selftest: {failures} failure(s)");
        return failures == 0 ? 0 : 1;
    }
}
