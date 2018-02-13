workspace(name = "j2objc")


maven_jar(
    name = "com_google_guava_guava",
    artifact = "com.google.guava:guava:24.0-jre",
)

maven_jar(
    name = "org_bitbucket_mstrobel_procyon_compilertools",
    artifact = 'org.bitbucket.mstrobel:procyon-compilertools:0.5.32',
)

maven_jar(
    name = "org_bitbucket_mstrobel_procyon_core",
    artifact = 'org.bitbucket.mstrobel:procyon-core:0.5.32',
)

maven_jar(
    name = "junit_junit",
    artifact = 'junit:junit:4.12',
)

maven_jar(
    name = "com_google_code_findbugs_jsr30",
    artifact = 'com.google.code.findbugs:jsr305:3.0.2',
)

protobuf_version = "3.5.1"

http_archive(
    name = "com_google_protobuf",
    sha256 = "1f8b9b202e9a4e467ff0b0f25facb1642727cdf5e69092038f15b37c75b99e45",
    strip_prefix = "protobuf-" + protobuf_version,
    url = "https://github.com/google/protobuf/archive/v" + protobuf_version + ".zip",
)

new_local_repository(
    name = "bazel_j2objc",
    path = "empty",
    build_file = "BUILD.bazel_j2objc",
)
