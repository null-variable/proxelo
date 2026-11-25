-- Prints one machine-readable line at the end of a wrk or wrk2 run.
-- Both tools record latency in microseconds.
done = function(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    'BENCH {"durationUs":%.0f,"requests":%.0f,"bytes":%.0f,' ..
    '"errors":{"connect":%.0f,"read":%.0f,"write":%.0f,"status":%.0f,"timeout":%.0f},' ..
    '"latencyUs":{"mean":%.1f,"p50":%.0f,"p90":%.0f,"p99":%.0f,"p999":%.0f,"max":%.0f}}\n',
    summary.duration, summary.requests, summary.bytes,
    e.connect, e.read, e.write, e.status, e.timeout,
    latency.mean, latency:percentile(50), latency:percentile(90),
    latency:percentile(99), latency:percentile(99.9), latency.max))
end
