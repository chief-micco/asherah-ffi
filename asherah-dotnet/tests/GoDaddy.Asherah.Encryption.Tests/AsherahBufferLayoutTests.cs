using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Pins the C# <see cref="AsherahBuffer"/> struct to the Rust
/// <c>#[repr(C)] struct AsherahBuffer { data, len, capacity }</c> ABI.
///
/// The Rust side always writes THREE pointer-sized fields to the buffer
/// pointer the caller supplied (<c>asherah-ffi/src/lib.rs:48-54</c>). If
/// the C# side declares fewer, every encrypt/decrypt call writes past
/// the caller's stack slot for <c>ref buffer</c> and stomps whatever
/// local the JIT parked next to it — the source of the sporadic
/// <c>NullReferenceException</c> from <c>DecryptBytes</c> under load.
/// The follow-up read in <c>asherah_buffer_free</c> then feeds a garbage
/// capacity to <c>Vec::from_raw_parts</c>, which is UB and can corrupt
/// the managed heap.
/// </summary>
public class AsherahBufferLayoutTests
{
    static AsherahBufferLayoutTests()
    {
        Environment.SetEnvironmentVariable(
            "STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
                ?? "2222222222222222222222222222222222222222222222222222222222222222");
        TestNativeLibraryPath.EnsureConfigured();
        RegisterTestAssemblyResolver();
    }

    // NativeLibraryLoader registers only for the production assembly. Our
    // direct P/Invokes here live in the test assembly, so we need a
    // resolver of our own that consults the same ASHERAH_DOTNET_NATIVE
    // environment variable.
    private static bool _testResolverRegistered;
    private static void RegisterTestAssemblyResolver()
    {
        if (_testResolverRegistered) return;
        NativeLibrary.SetDllImportResolver(
            typeof(AsherahBufferLayoutTests).Assembly,
            (name, asm, path) =>
            {
                if (!string.Equals(name, "asherah_ffi", StringComparison.Ordinal))
                {
                    return IntPtr.Zero;
                }
                var root = Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE");
                if (string.IsNullOrWhiteSpace(root))
                {
                    return NativeLibrary.Load(name, asm, path);
                }
                var file = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? "asherah_ffi.dll"
                    : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                        ? "libasherah_ffi.dylib"
                        : "libasherah_ffi.so";
                return NativeLibrary.Load(System.IO.Path.Join(root, file));
            });
        _testResolverRegistered = true;
    }

    /// <summary>
    /// Direct size assertion. The Rust struct is 3 * sizeof(usize); the
    /// C# struct must match. This is deterministic and fails immediately
    /// on the current binding (16 bytes vs. the required 24 on 64-bit).
    /// </summary>
    [Fact]
    public void AsherahBuffer_MatchesRustAbi_Size()
    {
        var expected = 3 * IntPtr.Size;
        var actual = Marshal.SizeOf<AsherahBuffer>();
        Assert.True(
            actual == expected,
            $"AsherahBuffer must be {expected} bytes to match Rust's " +
            $"#[repr(C)] struct AsherahBuffer {{ data, len, capacity }}. " +
            $"Actual size is {actual} bytes — every FFI call overflows " +
            $"the caller's stack slot by {expected - actual} bytes.");
    }

    /// <summary>
    /// Runtime overflow proof: allocate a byte scratch large enough for
    /// <see cref="AsherahBuffer"/> + a fenced sentinel region past it,
    /// alias the first sizeof(AsherahBuffer) bytes as the production
    /// struct, pre-fill the trailing sentinel bytes, and call
    /// <c>asherah_encrypt_to_json</c>. If the production struct is
    /// correctly sized to match Rust's ABI, the sentinel bytes MUST
    /// survive the call. If the production struct is too small, Rust
    /// writes past its end and stomps the sentinel — the stack-overflow
    /// bug we're chasing.
    /// </summary>
    [Fact]
    public unsafe void Encrypt_MustNotWritePastProductionBuffer()
    {
        using var factory = AsherahFactory.FromConfig(BuildConfig());
        using var session = factory.GetSession("layout-probe");

        var handleField = typeof(AsherahSession).GetField(
            "_handle", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(handleField);
        var safeHandle = (SafeHandle)handleField!.GetValue(session)!;
        var raw = safeHandle.DangerousGetHandle();

        var prodSize = Marshal.SizeOf<AsherahBuffer>();
        const int FenceBytes = 16; // enough to catch even a two-usize overflow
        Span<byte> scratch = stackalloc byte[prodSize + FenceBytes];
        const byte SentinelByte = 0x77;
        scratch.Slice(prodSize).Fill(SentinelByte);

        fixed (byte* scratchPtr = scratch)
        {
            ref var prodBuffer = ref Unsafe.AsRef<AsherahBuffer>(scratchPtr);
            prodBuffer = default;

            var plaintext = Encoding.UTF8.GetBytes("stack-overflow-probe");
            int status;
            fixed (byte* p = plaintext)
            {
                status = NativeMethods.asherah_encrypt_to_json(
                    raw, p, new UIntPtr((ulong)plaintext.LongLength), ref prodBuffer);
            }
            Assert.Equal(0, status);

            // Count how many fence bytes got clobbered by the FFI call.
            var fence = scratch.Slice(prodSize);
            var clobbered = 0;
            for (var i = 0; i < fence.Length; i++)
            {
                if (fence[i] != SentinelByte) clobbered++;
            }

            // Snapshot for the free call before we assert (which may
            // throw and leak — but leaking here is OK, the process exits
            // shortly after a test failure).
            var freeBuf = new AsherahBufferProbe
            {
                Data = prodBuffer.data,
                Len = prodBuffer.len,
                // If the C# struct is too small, Rust wrote its Vec
                // capacity into the fence — recover it so free is safe.
                Capacity = prodSize < 3 * IntPtr.Size
                    ? new UIntPtr(*(ulong*)(scratchPtr + 2 * IntPtr.Size))
                    : new UIntPtr((ulong)((UIntPtr)prodBuffer.len).ToUInt64()),
            };
            ProbeFree(ref freeBuf);

            Assert.True(
                clobbered == 0,
                $"Rust wrote {clobbered} byte(s) past the end of " +
                $"sizeof(AsherahBuffer)={prodSize}. This is the stack " +
                $"overflow that produces sporadic NREs from DecryptBytes " +
                $"under load — add the missing 'capacity' field to " +
                $"AsherahBuffer so it matches Rust's #[repr(C)] layout.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AsherahBufferProbe
    {
        public IntPtr Data;
        public UIntPtr Len;
        public UIntPtr Capacity;
    }

    [DllImport("asherah_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "asherah_buffer_free")]
    private static extern void ProbeFree(ref AsherahBufferProbe buffer);

    private static AsherahConfig BuildConfig()
    {
        return AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.TestDebugStatic)
            .Build();
    }
}
