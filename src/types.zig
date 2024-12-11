// const CVSS4_HEADER = "CVSS:4.0";

pub const CvssScore = struct {
    score: u8,
    level: CVSS_LEVEL,
};

pub const CVSS = union(CVSS_VERSION) {
    CVSS20: CvssScore,
    CVSS30: CvssScore,
    CVSS31: CvssScore,
    CVSS40: CvssScore,
};

pub const CVSS_VERSION = enum {
    CVSS20,
    CVSS30,
    CVSS31,
    CVSS40,
};

pub const CVSS_LEVEL = enum {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
};

pub const CvssParseError = error{
    NotCVSSString,
    UnknownMetricValue,
    UnknownMetricName,
    DuplicateMetric,
    MissingRequiredMetrics,
};
