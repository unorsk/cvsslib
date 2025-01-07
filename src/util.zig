const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = allocator.allocator();

pub fn debug(
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime !builtin.target.isWasm()) {
        std.log.debug(format, args);
    }
}

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    if (comptime builtin.target.isWasm()) {
        unreachable;
    } else {
        debug(format, args);
        std.process.exit(1);
    }
}
