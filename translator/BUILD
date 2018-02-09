java_binary(
    name = "translator",
    srcs = glob(["src/main/java/**/*.java"]),
    main_class = "com.google.devtools.j2objc.J2ObjC",
    resources = glob(["src/main/resources/com/google/**"]),
    deps = [
        "//annotations/src/main/java/com/google/j2objc/annotations",
        "@com_google_code_findbugs_jsr30//jar",
        "@com_google_guava_guava//jar",
        "@junit_junit//jar",
        "@local_jdk//:langtools-neverlink",
        "@org_bitbucket_mstrobel_procyon_compilertools//jar",
        "@org_bitbucket_mstrobel_procyon_core//jar",
    ],
)
