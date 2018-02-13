
java_import(
    name = "langtools",
    jars = ["@local_jdk//:langtools"],
)
java_library(
    name = "translator",
    srcs = glob(["src/main/java/**/*.java"]),
    resources = glob(["src/main/resources/com/google/**"]),
    deps = [
        "//annotations/src/main/java/com/google/j2objc/annotations",
        "@com_google_code_findbugs_jsr30//jar",
        "@com_google_guava_guava//jar",
        "@junit_junit//jar",
        ":langtools",
        "@org_bitbucket_mstrobel_procyon_compilertools//jar",
        "@org_bitbucket_mstrobel_procyon_core//jar",
    ],
    visibility = ["//tools/j2objc:__pkg__"],
)
