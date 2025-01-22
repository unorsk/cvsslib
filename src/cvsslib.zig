const builtin = @import("builtin");
const types = @import("types.zig");
const std = @import("std");
const cvss31 = @import("./cvss31.zig");
const cvss40 = @import("./cvss40.zig");
const consoleLog = @import("./util.zig").consoleLog;
const fatal = @import("./util.zig").fatal;
const testing = std.testing;

const CVSS20_HEADER = "CVSS:2.0";
const CVSS30_HEADER = "CVSS:3.0";
const CVSS31_HEADER = "CVSS:3.1";
const CVSS40_HEADER = "CVSS:4.0";

export fn allocate(size: usize) ?[*]u8 {
    if (builtin.target.isWasm()) {
        const result = std.heap.wasm_allocator.alloc(u8, size) catch return null;
        return result.ptr;
    }
    return null;
}

export fn deallocate(ptr: [*]u8, size: usize) void {
    if (builtin.target.isWasm()) {
        std.heap.wasm_allocator.free(ptr[0..size]);
    }
}

pub export fn cvssScoreWasm(cvss: [*]const u8, len: usize) ?[*]u8 {
    const hello = "Hello";
    if (comptime builtin.target.isWasm()) {
        consoleLog(hello.ptr, hello.len);
        consoleLog(cvss, len);
        consoleLog(cvss, 4);
    }
    const cvss_result = (cvssScore(cvss[0 .. len - 1])) catch types.CVSS{ .version = .CVSS20, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } }; //TODO
    // return types.CVSS{ .version = .CVSS20, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } }; //TODO
    const result = std.heap.wasm_allocator.create(types.CVSS) catch {
        consoleLog("Memory allocation failed".ptr, 25);
        return null;
    };

    result.* = cvss_result;

    return @ptrCast(result);
}

pub fn cvssScore(cvss: []const u8) !types.CVSS {
    const version = try detectCvssVersion(cvss);
    switch (version) {
        types.CVSS_VERSION.CVSS20 => {
            fatal("CVSS20 Not imeplemented", .{});
            // return types.CVSS{ .version = .CVSS20, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS30 => {
            fatal("CVSS30 Not imeplemented", .{});
            // return types.CVSS{ .version = .CVSS30, .score = .{ .score = 0, .level = types.CVSS_LEVEL.NONE } };
        },
        types.CVSS_VERSION.CVSS31 => {
            return types.CVSS{ .version = .CVSS31, .score = try cvss31.score(cvss[CVSS31_HEADER.len..]) };
        },
        types.CVSS_VERSION.CVSS40 => {
            return types.CVSS{ .version = .CVSS40, .score = try cvss40.score(cvss[CVSS31_HEADER.len..]) };
        },
    }
}

fn detectCvssVersion(cvss: []const u8) types.CvssParseError!types.CVSS_VERSION {
    if (std.mem.eql(u8, cvss[0..CVSS20_HEADER.len], CVSS20_HEADER)) {
        return types.CVSS_VERSION.CVSS20;
    } else if (std.mem.eql(u8, cvss[0..CVSS30_HEADER.len], CVSS30_HEADER)) {
        return types.CVSS_VERSION.CVSS30;
    } else if (std.mem.eql(u8, cvss[0..CVSS31_HEADER.len], CVSS31_HEADER)) {
        return types.CVSS_VERSION.CVSS31;
    } else if (std.mem.eql(u8, cvss[0..CVSS40_HEADER.len], CVSS40_HEADER)) {
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
