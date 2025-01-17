const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const cvss = @import("types.zig");

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = allocator.allocator();

pub extern fn consoleLog(msg: [*]const u8, le: usize) void;

pub fn debug(
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime !builtin.target.isWasm()) {
        std.log.debug(format, args);
    }
}

// zig fmt: off
pub fn levelFromScore(score: f32) cvss.CVSS_LEVEL {
    return if (score == 0.0) cvss.CVSS_LEVEL.NONE
        else if (score < 4.0) cvss.CVSS_LEVEL.LOW
        else if (score < 7.0) cvss.CVSS_LEVEL.MEDIUM
        else if (score < 9.0) cvss.CVSS_LEVEL.HIGH
        else if (score <= 10.0) cvss.CVSS_LEVEL.CRITICAL
        else unreachable;
}
// zig fmt: on

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    if (comptime builtin.target.isWasm()) {
        consoleLog(format.ptr, format.len);
        unreachable;
    } else {
        debug(format, args);
        std.process.exit(1);
    }
}
