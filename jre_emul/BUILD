load(
    ":build_files.bzl",
    "JAVA_SOURCES",
    "JAVA_PUBLIC_SOURCES_CORE",
    "JAVA_PRIVATE_SOURCES_CORE",
    "JAVA_PUBLIC_SOURCES_CONCURRENT",
    "JAVA_PRIVATE_SOURCES_CONCURRENT",
    "EMULATED_JAVA_SOURCES",
    "SOURCE_RETENTION_ANNOTATIONS",
)
load("//tools/build_defs/j2objc:j2objc_jre_library.bzl", "j2objc_jre_library")

load(
    "@bazel_tools//tools/jdk:default_java_toolchain.bzl",
    "default_java_toolchain",
)

java_library(
    name = "all_jre_lib",
    srcs = JAVA_SOURCES + EMULATED_JAVA_SOURCES + SOURCE_RETENTION_ANNOTATIONS,
    javacopts = [
        "-XepDisableAllChecks",
    ],
    deps = [
        "//annotations/src/main/java/com/google/j2objc/annotations",
    ]
)

java_import(
    name = "all_jre",
    jars = ["liball_jre_lib.jar"],
)
default_java_toolchain(
    name = "jre_compile_java_toolchain",
    javac = ["@bazel_tools//third_party/java/jdk/langtools:javac_jar"],
#    javac = ["@bazel_tools//tools/jdk:platformclasspath.jar"],
    jvm_opts = ["-Xbootclasspath/p:$(location @bazel_tools//third_party/java/jdk/langtools:javac_jar)"],
    bootclasspath = [":all_jre"],
)

j2objc_jre_library(
    name = "source_retention_annotations",
    emulated_srcs = SOURCE_RETENTION_ANNOTATIONS,
    javacopts = [
        "-XepDisableAllChecks",
    ],
)

j2objc_jre_library(
    name = "jre_core",
    srcs = JAVA_PUBLIC_SOURCES_CORE,
    emulated_srcs = EMULATED_JAVA_SOURCES,
    javacopts = [
        "-XepDisableAllChecks",
        "-Xbootclasspath:",
    ],
    private_srcs = JAVA_PRIVATE_SOURCES_CORE,
    deps = [
        "//annotations/src/main/java/com/google/j2objc/annotations",
    ],
)

j2objc_jre_library(
    name = "jre_concurrent",
    srcs = JAVA_PUBLIC_SOURCES_CONCURRENT,
    javacopts = [
        "-XepDisableAllChecks",
    ],
    private_srcs = JAVA_PRIVATE_SOURCES_CONCURRENT,
    deps = [
        "//annotations/src/main/java/com/google/j2objc/annotations",
#        ":jre_core",
    ],
)
