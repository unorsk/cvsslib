const std = @import("std");
const types = @import("./types.zig");
const testing = std.testing;

fn eql(comptime T: type, a: []const T, b: []const T, i: usize) bool {
    return std.mem.eql(T, a[i..(i + b.len)], b);
}

fn parse_cvss31_metrics(cvss: []const u8) ![]types.Cvss31Metric {
    var metrics = std.ArrayList(types.Cvss31Metric).init(std.heap.page_allocator);

    const copyCvss31Decl = try std.heap.page_allocator.dupe(types.Cvss31MetricDecl, types.Cvss31Decl);
    defer std.heap.page_allocator.free(copyCvss31Decl);

    var it = std.mem.tokenizeScalar(u8, cvss, '/');
    while (it.next()) |pair| {
        var itMetric = std.mem.tokenizeScalar(u8, pair, ':');
        const metricTypeRaw = itMetric.next();
        if (metricTypeRaw == null) {
            return types.CvssParseError.NotCVSSString;
        }

        var metricType: ?types.Cvss31MetricType = null;
        for (copyCvss31Decl) |*decl| {
            if (std.mem.eql(u8, metricTypeRaw.?, decl.metricTypeValue)) {
                if (decl.isRead == true) {
                    return types.CvssParseError.DuplicateMetric;
                }
                metricType = decl.metricType;
                decl.*.isRead = true;

                const metricValueRaw = itMetric.rest();

                var metricValue: ?[]const u8 = null;
                for (0..(decl.possibleValues.len)) |j| {
                    if (std.mem.eql(u8, metricValueRaw, decl.possibleValues[j])) {
                        metricValue = decl.possibleValues[j];
                        try metrics.append(.{ .metricType = metricType.?, .value = metricValue.? });
                        break;
                    }
                }
                if (metricValue == null) {
                    std.debug.print("metric raw: {s}\n", .{metricValueRaw});
                    std.debug.print("metric type: {}\n", .{metricType.?});
                    std.debug.print("token: {s}\n", .{pair});
                    return types.CvssParseError.UnknownMetricValue;
                }

                break;
            }
        }
        if (metricType == null) {
            return types.CvssParseError.UnknownMetricName;
        }
    }

    for (copyCvss31Decl) |decl| {
        if (decl.required and !decl.isRead) {
            return types.CvssParseError.MissingRequiredMetrics;
        }
    }

    return metrics.items;
}

test "parse duplicate metric CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/AV:N";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(types.CvssParseError.DuplicateMetric, err);
}

test "parse CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
    const cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const metrics = try parse_cvss31_metrics(cvss);
    try testing.expectEqual(8, metrics.len);
    try testing.expectEqual(types.Cvss31MetricType.AV, metrics[0].metricType);
    try testing.expectEqual("N", metrics[0].value);
    try testing.expectEqual(types.Cvss31MetricType.AC, metrics[1].metricType);
    try testing.expectEqual("L", metrics[1].value);
    try testing.expectEqual(types.Cvss31MetricType.PR, metrics[2].metricType);
    try testing.expectEqual("L", metrics[2].value);
    try testing.expectEqual(types.Cvss31MetricType.UI, metrics[3].metricType);
    try testing.expectEqual("N", metrics[3].value);
    try testing.expectEqual(types.Cvss31MetricType.S, metrics[4].metricType);
    try testing.expectEqual("U", metrics[4].value);
    try testing.expectEqual(types.Cvss31MetricType.C, metrics[5].metricType);
    try testing.expectEqual("H", metrics[5].value);
    try testing.expectEqual(types.Cvss31MetricType.I, metrics[6].metricType);
    try testing.expectEqual("H", metrics[6].value);
    try testing.expectEqual(types.Cvss31MetricType.A, metrics[7].metricType);
    try testing.expectEqual("H", metrics[7].value);
}

test "parse simple AV metric unknown value" {
    const cvss = "AV:Z";
    const err = parse_cvss31_metrics(cvss);
    try testing.expectError(types.CvssParseError.UnknownMetricValue, err);
}
