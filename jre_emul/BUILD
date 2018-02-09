
load(":build_files.bzl", "JAVA_SOURCES", "EMULATED_JAVA_SOURCES")

java_library(
    name = "jre_emul",
    srcs = JAVA_SOURCES + EMULATED_JAVA_SOURCES,
    javacopts = [
        "-XepDisableAllChecks",
    ],
    deps = ["//annotations/src/main/java/com/google/j2objc/annotations"],
)
