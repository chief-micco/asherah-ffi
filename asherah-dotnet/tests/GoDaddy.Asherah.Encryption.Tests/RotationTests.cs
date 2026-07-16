// Rotation, revocation, and sync↔async interop tests for the
// asherah-dotnet binding.
//
// The Rust core has comprehensive rotation/revocation coverage in
// asherah/tests/. The .NET binding had **zero** rotation tests.
// Mirrors the asherah-node, asherah-py, and asherah-java rotation
// suites.
//
// Hermetic: MetastoreKind.Memory + KmsKind.TestDebugStatic produces
// a hermetic factory with no Docker or network dependency.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

public class RotationTests
{
    static RotationTests()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            // Match the path-resolution used by RoundTripTests so the
            // native asherah_dotnet.{so,dylib,dll} from cargo build
            // is found.
            var root = TestNativeLibraryPath.LocateRepoRoot();
            Environment.SetEnvironmentVariable(
                "ASHERAH_DOTNET_NATIVE",
                System.IO.Path.Join(root, "target", "debug"));
        }
    }

    private static AsherahConfig ShortExpiryConfig(string suffix)
    {
        return AsherahConfig.CreateBuilder()
            .WithServiceName($"rot-{suffix}-svc")
            .WithProductId($"rot-{suffix}-prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.TestDebugStatic)
            .WithExpireAfter(TimeSpan.FromSeconds(1))
            .WithCheckInterval(TimeSpan.FromSeconds(1))
            .WithEnableSessionCaching(false)
            .Build();
    }

    /// <summary>Pull <c>Key.ParentKeyMeta.Created</c> out of a DRR JSON string.</summary>
    private static long IkCreated(string drrJson)
    {
        // Cheap JSON extract — the core uses Pascal-cased fields, and
        // we only need a single integer. Avoids a JSON dependency.
        int parentIdx = drrJson.IndexOf("\"ParentKeyMeta\"", StringComparison.Ordinal);
        Assert.True(parentIdx >= 0, $"DRR missing ParentKeyMeta: {drrJson}");
        int createdIdx = drrJson.IndexOf("\"Created\"", parentIdx, StringComparison.Ordinal);
        Assert.True(createdIdx >= 0, $"ParentKeyMeta missing Created: {drrJson}");
        int colon = drrJson.IndexOf(':', createdIdx);
        int i = colon + 1;
        while (i < drrJson.Length && char.IsWhiteSpace(drrJson[i])) i++;
        int start = i;
        if (i < drrJson.Length && drrJson[i] == '-') i++;
        while (i < drrJson.Length && char.IsDigit(drrJson[i])) i++;
        return long.Parse(drrJson.Substring(start, i - start));
    }

    // ──────────── Sync rotation ────────────

    [Fact]
    public void SyncRotationAcrossExpiry()
    {
        AsherahApi.Setup(ShortExpiryConfig("sync"));
        try
        {
            var drr1 = AsherahApi.EncryptString("p1", "before");
            var ik1 = IkCreated(drr1);

            Thread.Sleep(3000);

            var drr2 = AsherahApi.EncryptString("p1", "after");
            var ik2 = IkCreated(drr2);

            Assert.True(ik2 > ik1,
                $"expected IK rotation across expiry: ik2={ik2} should be > ik1={ik1}");
            Assert.Equal("before", AsherahApi.DecryptString("p1", drr1));
            Assert.Equal("after", AsherahApi.DecryptString("p1", drr2));
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }

    // ──────────── Async rotation ────────────

    [Fact]
    public async Task AsyncRotationAcrossExpiry()
    {
        await AsherahApi.SetupAsync(ShortExpiryConfig("async"));
        try
        {
            var drr1 = await AsherahApi.EncryptAsync("p1", Encoding.UTF8.GetBytes("before-async"));
            var ik1 = IkCreated(Encoding.UTF8.GetString(drr1));

            await Task.Delay(3000, TestContext.Current.CancellationToken);

            var drr2 = await AsherahApi.EncryptAsync("p1", Encoding.UTF8.GetBytes("after-async"));
            var ik2 = IkCreated(Encoding.UTF8.GetString(drr2));

            Assert.True(ik2 > ik1,
                $"async path must rotate IK across expiry: ik2={ik2} should be > ik1={ik1}");
            Assert.Equal("before-async",
                Encoding.UTF8.GetString(await AsherahApi.DecryptAsync("p1", drr1)));
            Assert.Equal("after-async",
                Encoding.UTF8.GetString(await AsherahApi.DecryptAsync("p1", drr2)));
        }
        finally
        {
            await AsherahApi.ShutdownAsync();
        }
    }

    // ──────────── Sync↔async interop after rotation ────────────

    [Fact]
    public async Task SyncAsyncInteropAfterRotation()
    {
        AsherahApi.Setup(ShortExpiryConfig("interop"));
        try
        {
            var drrSyncPre = AsherahApi.EncryptString("p1", "sync-pre");
            var drrAsyncPre = await AsherahApi.EncryptAsync("p1", Encoding.UTF8.GetBytes("async-pre"));

            await Task.Delay(3000, TestContext.Current.CancellationToken);

            var drrSyncPost = AsherahApi.EncryptString("p1", "sync-post");
            var drrAsyncPost = await AsherahApi.EncryptAsync("p1", Encoding.UTF8.GetBytes("async-post"));

            // Confirm rotation actually happened — at least one post-DRR
            // has a strictly newer IK than both pre-DRRs.
            var preMax = Math.Max(IkCreated(drrSyncPre),
                                  IkCreated(Encoding.UTF8.GetString(drrAsyncPre)));
            var postMin = Math.Min(IkCreated(drrSyncPost),
                                   IkCreated(Encoding.UTF8.GetString(drrAsyncPost)));
            Assert.True(postMin > preMax,
                $"interop path must rotate: postMin={postMin} should be > preMax={preMax}");

            // 8 round-trips: every encrypt × every decrypt path.
            Assert.Equal("sync-pre", AsherahApi.DecryptString("p1", drrSyncPre));
            Assert.Equal("sync-pre", Encoding.UTF8.GetString(
                await AsherahApi.DecryptAsync("p1", Encoding.UTF8.GetBytes(drrSyncPre))));
            Assert.Equal("async-pre", Encoding.UTF8.GetString(
                AsherahApi.Decrypt("p1", drrAsyncPre)));
            Assert.Equal("async-pre", Encoding.UTF8.GetString(
                await AsherahApi.DecryptAsync("p1", drrAsyncPre)));
            Assert.Equal("sync-post", AsherahApi.DecryptString("p1", drrSyncPost));
            Assert.Equal("sync-post", Encoding.UTF8.GetString(
                await AsherahApi.DecryptAsync("p1", Encoding.UTF8.GetBytes(drrSyncPost))));
            Assert.Equal("async-post", Encoding.UTF8.GetString(
                AsherahApi.Decrypt("p1", drrAsyncPost)));
            Assert.Equal("async-post", Encoding.UTF8.GetString(
                await AsherahApi.DecryptAsync("p1", drrAsyncPost)));
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }

    // ──────────── Multiple rotation cycles ────────────

    [Fact]
    public async Task MultipleRotationCycles()
    {
        await AsherahApi.SetupAsync(ShortExpiryConfig("multi"));
        try
        {
            var drrs = new System.Collections.Generic.List<byte[]>();
            var payloads = new System.Collections.Generic.List<byte[]>();
            var iks = new System.Collections.Generic.List<long>();
            for (int i = 0; i < 3; i++)
            {
                var payload = Encoding.UTF8.GetBytes($"cycle-{i}");
                var drr = await AsherahApi.EncryptAsync("p1", payload);
                drrs.Add(drr);
                payloads.Add(payload);
                iks.Add(IkCreated(Encoding.UTF8.GetString(drr)));
                await Task.Delay(3000, TestContext.Current.CancellationToken);
            }

            // Each cycle's IK must be strictly newer than the previous.
            for (int i = 1; i < iks.Count; i++)
            {
                Assert.True(iks[i] > iks[i - 1],
                    $"cycle {i}: ik={iks[i]} should be > prev ik={iks[i - 1]}");
            }

            // Every historical DRR still decrypts.
            for (int i = 0; i < drrs.Count; i++)
            {
                var recovered = await AsherahApi.DecryptAsync("p1", drrs[i]);
                Assert.Equal(payloads[i], recovered);
            }
        }
        finally
        {
            await AsherahApi.ShutdownAsync();
        }
    }
}
