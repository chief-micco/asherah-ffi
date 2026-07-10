using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Reproduces the NullReferenceException that surfaces from
/// <see cref="AsherahSession.DecryptBytes"/> when many threads concurrently
/// acquire and dispose sessions for the same partition through a single
/// factory with session caching enabled.
///
/// The production symptom: an app pulling sessions from an
/// <see cref="AsherahFactory"/> via <c>using</c> scopes on many threads,
/// against a hot partition, occasionally throws NRE out of
/// <c>DecryptBytes</c> under load.
/// </summary>
public class MultiThreadedSessionCacheTests
{
    private const string PartitionId = "multi-threaded-session-cache";
    private const int PayloadCount = 5;
    private const int WorkerThreads = 64;
    // Run for a duration rather than an op-count so both the session-cache
    // TTL and the intermediate-key ExpireAfter have multiple windows to
    // fire mid-run. 30s gives ~30 expiry cycles at 1s TTL.
    private static readonly TimeSpan WorkerDuration = TimeSpan.FromSeconds(30);

    static MultiThreadedSessionCacheTests()
    {
        Environment.SetEnvironmentVariable(
            "STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
                ?? "2222222222222222222222222222222222222222222222222222222222222222");
        TestNativeLibraryPath.EnsureConfigured();
    }

    private static AsherahConfig BuildConfig()
    {
        // Stack every expiry knob at its minimum (1s) so that during a
        // multi-second run BOTH the session cache entry AND the underlying
        // intermediate-key entry are being reloaded on the fly under
        // concurrent decrypts. Production symptom takes "a little time" to
        // appear which points at TTL-driven eviction racing with an
        // in-flight decrypt.
        return AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.TestDebugStatic)
            .WithEnableSessionCaching(true)
            .WithSessionCacheMaxSize(16)
            .WithSessionCacheDuration(TimeSpan.FromSeconds(1))
            .WithExpireAfter(TimeSpan.FromSeconds(1))
            .WithCheckInterval(TimeSpan.FromSeconds(1))
            .Build();
    }

    [Fact]
    public async Task ConcurrentGetSession_DecryptFromSharedPartition_ShouldNotThrow()
    {
        using var factory = AsherahFactory.FromConfig(BuildConfig());

        // 1. Pre-encrypt 5 payloads under a single partition, then dispose
        //    the producer so subsequent workers hit the session cache path
        //    (cold on first miss, hot thereafter).
        var plaintexts = new string[PayloadCount];
        var ciphertexts = new string[PayloadCount];
        using (var producer = factory.GetSession(PartitionId))
        {
            for (var i = 0; i < PayloadCount; i++)
            {
                plaintexts[i] = $"multi-threaded-payload-{i}-{Guid.NewGuid():N}";
                ciphertexts[i] = producer.EncryptString(plaintexts[i]);
            }
        }

        // 2. Fan out N threads, each acquires+disposes its own session for
        //    the SAME partition, decrypts a randomly-chosen ciphertext, and
        //    validates the plaintext round-trips. Any exception (NRE,
        //    ObjectDisposedException, AsherahException, mismatch, …) is
        //    collected and surfaced at the end.
        var errors = new ConcurrentQueue<Exception>();
        var mismatches = new ConcurrentQueue<string>();
        using var startGate = new Barrier(WorkerThreads);
        var tasks = new Task[WorkerThreads];

        var ct = TestContext.Current.CancellationToken;
        var deadline = DateTime.UtcNow + WorkerDuration;
        for (var t = 0; t < WorkerThreads; t++)
        {
            var seed = t;
            tasks[t] = Task.Run(() =>
            {
                var rng = new Random(seed);
                // Release all workers at once to maximise contention on the
                // factory's session cache and dispose paths.
                startGate.SignalAndWait(ct);

                var op = 0;
                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        using var session = factory.GetSession(PartitionId);
                        var idx = rng.Next(PayloadCount);
                        var recovered = session.DecryptString(ciphertexts[idx]);
                        if (!string.Equals(recovered, plaintexts[idx], StringComparison.Ordinal))
                        {
                            mismatches.Enqueue(
                                $"thread={seed} op={op} idx={idx} " +
                                $"expected='{plaintexts[idx]}' got='{recovered}'");
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Enqueue(ex);
                    }
                    op++;
                }
            }, ct);
        }

        await Task.WhenAll(tasks);

        // Report NRE separately so the failure message clearly identifies
        // the production symptom this test is chasing.
        var nreCount = 0;
        foreach (var e in errors)
        {
            if (e is NullReferenceException)
            {
                nreCount++;
            }
        }

        Assert.True(
            errors.IsEmpty && mismatches.IsEmpty,
            $"concurrent decrypt on shared partition failed: " +
            $"errors={errors.Count} (NRE={nreCount}), mismatches={mismatches.Count}\n" +
            $"first error: {(errors.TryPeek(out var first) ? first.ToString() : "<none>")}\n" +
            $"first mismatch: {(mismatches.TryPeek(out var m) ? m : "<none>")}");
    }

    /// <summary>
    /// Second variant: the same pattern but rotating over many partitions
    /// while the native session-cache bound is small. This forces the cache
    /// to evict and reconstruct entries constantly, so
    /// <c>factory.GetSession</c> and <c>session.Dispose</c> race with cache
    /// eviction on adjacent partitions. Closer to real production factories
    /// serving many hot tenants through one shared factory.
    /// </summary>
    [Fact]
    public async Task ConcurrentGetSession_WithCacheChurn_ShouldNotThrow()
    {
        const int Partitions = 128;
        const int Threads = 64;
        var duration = TimeSpan.FromSeconds(30);

        // Cache size deliberately below the partition count AND a 1s TTL so
        // every GetSession has a real chance of triggering either a size
        // eviction or a TTL eviction on a partition another thread is
        // mid-use on. IK expiry also at 1s to churn the intermediate-key
        // cache concurrently with session-cache eviction.
        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.TestDebugStatic)
            .WithEnableSessionCaching(true)
            .WithSessionCacheMaxSize(8)
            .WithSessionCacheDuration(TimeSpan.FromSeconds(1))
            .WithExpireAfter(TimeSpan.FromSeconds(1))
            .WithCheckInterval(TimeSpan.FromSeconds(1))
            .Build();

        using var factory = AsherahFactory.FromConfig(config);

        // Pre-encrypt one payload per partition through the factory.
        var partitions = new string[Partitions];
        var plaintexts = new string[Partitions];
        var ciphertexts = new string[Partitions];
        for (var i = 0; i < Partitions; i++)
        {
            partitions[i] = $"tenant-{i}";
            plaintexts[i] = $"payload-{i}-{Guid.NewGuid():N}";
            using var producer = factory.GetSession(partitions[i]);
            ciphertexts[i] = producer.EncryptString(plaintexts[i]);
        }

        var errors = new ConcurrentQueue<Exception>();
        var mismatches = new ConcurrentQueue<string>();
        using var startGate = new Barrier(Threads);
        var tasks = new Task[Threads];

        var ct = TestContext.Current.CancellationToken;
        var deadline = DateTime.UtcNow + duration;
        for (var t = 0; t < Threads; t++)
        {
            var seed = t;
            tasks[t] = Task.Run(() =>
            {
                var rng = new Random(seed * 1013 + 17);
                startGate.SignalAndWait(ct);

                var op = 0;
                while (DateTime.UtcNow < deadline)
                {
                    var idx = rng.Next(Partitions);
                    try
                    {
                        using var session = factory.GetSession(partitions[idx]);
                        var recovered = session.DecryptString(ciphertexts[idx]);
                        if (!string.Equals(recovered, plaintexts[idx], StringComparison.Ordinal))
                        {
                            mismatches.Enqueue(
                                $"thread={seed} op={op} partition={partitions[idx]} " +
                                $"expected='{plaintexts[idx]}' got='{recovered}'");
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Enqueue(ex);
                    }
                    op++;
                }
            }, ct);
        }

        await Task.WhenAll(tasks);

        var nreCount = 0;
        foreach (var e in errors)
        {
            if (e is NullReferenceException)
            {
                nreCount++;
            }
        }

        Assert.True(
            errors.IsEmpty && mismatches.IsEmpty,
            $"cache-churn decrypt failed: " +
            $"errors={errors.Count} (NRE={nreCount}), mismatches={mismatches.Count}\n" +
            $"first error: {(errors.TryPeek(out var first) ? first.ToString() : "<none>")}\n" +
            $"first mismatch: {(mismatches.TryPeek(out var m) ? m : "<none>")}");
    }
}
