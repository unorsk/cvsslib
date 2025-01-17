const types = @import("types.zig");
const std = @import("std");
const cvss31 = @import("./cvss31.zig");
const consoleLog = @import("./util.zig").consoleLog;
const testing = std.testing;

const CVSS20_HEADER = "CVSS:2.0";
const CVSS30_HEADER = "CVSS:3.0";
const CVSS31_HEADER = "CVSS:3.1";
const CVSS40_HEADER = "CVSS:4.0";

export fn allocate(size: usize) ?[*]u8 {
    const result = std.heap.wasm_allocator.alloc(u8, size) catch return null;
    return result.ptr;
}

export fn deallocate(ptr: [*]u8, size: usize) void {
    std.heap.wasm_allocator.free(ptr[0..size]);
}

pub export fn cvssScoreWasm(cvss: [*]const u8, len: usize) types.CVSS {
    const hello = "Hello";
    consoleLog(hello.ptr, hello.len);
    return (cvssScore(cvss[0 .. len - 1])) catch types.CVSS{ .version = .CVSS20, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } }; //TODO
}

pub fn cvssScore(cvss: []const u8) !types.CVSS {
    const version = try detectCvssVersion(cvss);
    switch (version) {
        types.CVSS_VERSION.CVSS20 => {
            return types.CVSS{ .version = .CVSS20, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS30 => {
            return types.CVSS{ .version = .CVSS30, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS31 => {
            return types.CVSS{ .version = .CVSS31, .score = try cvss31.score(cvss[CVSS31_HEADER.len..]) };
        },
        types.CVSS_VERSION.CVSS40 => {
            return types.CVSS{ .version = .CVSS40, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
    }
}

fn detectCvssVersion(cvss: []const u8) types.CvssParseError!types.CVSS_VERSION {
    if (std.mem.eql(u8, cvss, CVSS20_HEADER)) {
        return types.CVSS_VERSION.CVSS20;
    } else if (std.mem.eql(u8, cvss, CVSS30_HEADER)) {
        return types.CVSS_VERSION.CVSS30;
    } else if (std.mem.eql(u8, cvss[0..CVSS31_HEADER.len], CVSS31_HEADER)) {
        return types.CVSS_VERSION.CVSS31;
    } else if (std.mem.eql(u8, cvss, CVSS40_HEADER)) {
        return types.CVSS_VERSION.CVSS40;
    } else {
        return types.CvssParseError.NotCVSSString;
    }
}

test "detect_cvss_version" {
    try testing.expect(try detectCvssVersion("CVSS:2.0") == types.CVSS_VERSION.CVSS20);
    try testing.expect(try detectCvssVersion("CVSS:3.0") == types.CVSS_VERSION.CVSS30);
    try testing.expect(try detectCvssVersion("CVSS:3.1") == types.CVSS_VERSION.CVSS31);
    try testing.expect(try detectCvssVersion("CVSS:4.0") == types.CVSS_VERSION.CVSS40);

    _ = detectCvssVersion("CVSS:5.0") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };

    _ = detectCvssVersion("") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };

    _ = detectCvssVersion(" ") catch |err| {
        try testing.expect(err == types.CvssParseError.NotCVSSString);
    };
}
