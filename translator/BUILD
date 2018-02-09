
java_binary(
    name = "translator",
    srcs = glob(["src/main/java/**/*.java"]),
    resources = glob(["src/main/resources/com/google/**"]),
    main_class = "com.google.devtools.j2objc.J2ObjC",
    deps = [
        "@com_google_guava_guava//jar",
        "@org_bitbucket_mstrobel_procyon_compilertools//jar",
        "@org_bitbucket_mstrobel_procyon_core//jar",
        "@com_google_code_findbugs_jsr30//jar",
        "@local_jdk//:langtools-neverlink",
        "@junit_junit//jar",
        "//annotations/src/main/java/com/google/j2objc/annotations",
    ]
)
